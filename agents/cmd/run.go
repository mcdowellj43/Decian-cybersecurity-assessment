package cmd

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"decian-agent/internal/client"
	"decian-agent/internal/config"
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"decian-agent/internal/network"
	"github.com/spf13/cobra"
)

const (
	jobStatusSucceeded = "SUCCEEDED"
	jobStatusFailed    = "FAILED"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the agent job loop",
	Long: `Connect to the jobs API, poll for work assigned to this agent,
and execute assessment jobs before reporting results back to the platform.`,
	RunE: runLoop,
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().Bool("list-modules", false, "List available assessment modules and exit")
	runCmd.Flags().Int("wait", 30, "Long poll wait duration in seconds")
}

func runLoop(cmd *cobra.Command, args []string) error {
	listModules, _ := cmd.Flags().GetBool("list-modules")
	if listModules {
		return listAvailableModules()
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	if cfg.Server.URL == "" {
		return fmt.Errorf("server URL not configured. Run 'decian-agent setup' first")
	}

	if cfg.Agent.ID == "" || cfg.Agent.Secret == "" {
		return fmt.Errorf("agent credentials missing. Run 'decian-agent setup' to register")
	}

	waitSeconds, _ := cmd.Flags().GetInt("wait")
	if waitSeconds <= 0 || waitSeconds > 60 {
		waitSeconds = 30
	}

	log := logger.NewLogger(cfg.Logging.Verbose)
	apiClient := client.NewAPIClient(cfg.Server.URL, log)
	dedupe := map[string]time.Time{}
	backoff := time.Second

	log.Info("Agent run loop started", map[string]interface{}{
		"agent_id": cfg.Agent.ID,
		"server":   cfg.Server.URL,
	})

	for {
		token, err := apiClient.MintAgentToken(cfg.Agent.ID, cfg.Agent.Secret)
		if err != nil {
			log.Error("Failed to mint agent token", map[string]interface{}{"error": err.Error()})
			time.Sleep(backoff)
			backoff = increaseBackoff(backoff)
			continue
		}

		backoff = time.Second
		tokenExpiry := time.Now().Add(time.Duration(token.ExpiresIn-60) * time.Second)

		for {
			if time.Now().After(tokenExpiry) {
				log.Debug("Agent token nearing expiry, refreshing", nil)
				break
			}

			jobs, err := apiClient.NextJobs(cfg.Agent.ID, token.AccessToken, waitSeconds)
			if err != nil {
				if errors.Is(err, client.ErrUnauthorized) {
					log.Warn("Agent token rejected by server", nil)
					break
				}

				log.Warn("Error while polling for jobs", map[string]interface{}{"error": err.Error()})
				time.Sleep(backoff)
				backoff = increaseBackoff(backoff)
				continue
			}

			backoff = time.Second

			if len(jobs) == 0 {
				pruneDedupeCache(dedupe)
				continue
			}

			for _, job := range jobs {
				if _, seen := dedupe[job.JobID]; seen {
					log.Debug("Skipping duplicate job", map[string]interface{}{"job_id": job.JobID})
					continue
				}
				dedupe[job.JobID] = time.Now()

				if err := apiClient.AckJob(job.JobID, token.AccessToken); err != nil {
					log.Error("Failed to acknowledge job", map[string]interface{}{"job_id": job.JobID, "error": err.Error()})
					continue
				}

				if err := apiClient.StartJob(job.JobID, token.AccessToken); err != nil {
					log.Error("Failed to start job", map[string]interface{}{"job_id": job.JobID, "error": err.Error()})
					continue
				}

				result := executeJob(job, cfg, log)
				payload := client.ResultPayload{Status: result.Status, Summary: result.Summary}

				if result.ArtifactPath != "" {
					log.Warn("Artifact upload requested but not implemented", map[string]interface{}{"job_id": job.JobID})
					// Future implementation: sign and upload artifact using apiClient.SignArtifactUpload
				}

				if err := apiClient.SubmitJobResults(job.JobID, token.AccessToken, payload); err != nil {
					log.Error("Failed to submit job results", map[string]interface{}{"job_id": job.JobID, "error": err.Error()})
				}
			}

			pruneDedupeCache(dedupe)
		}
	}
}

type jobExecutionResult struct {
	Status       string
	Summary      map[string]interface{}
	ArtifactPath string
}

func executeJob(job client.JobEnvelope, cfg *config.Config, log *logger.Logger) jobExecutionResult {
	switch strings.ToUpper(job.Type) {
	case "ASSESSMENT":
		payload, err := parseAssessmentPayload(job.Payload)
		if err != nil {
			log.Error("Invalid assessment job payload", map[string]interface{}{"job_id": job.JobID, "error": err.Error()})
			return jobExecutionResult{
				Status:  jobStatusFailed,
				Summary: map[string]interface{}{"error": err.Error()},
			}
		}
		return executeAssessmentJob(payload, cfg, log)
	default:
		log.Warn("Unsupported job type", map[string]interface{}{"job_type": job.Type})
		return jobExecutionResult{
			Status:  jobStatusFailed,
			Summary: map[string]interface{}{"error": "unsupported job type"},
		}
	}
}

type assessmentJobPayload struct {
	AssessmentID      string
	Modules           []string
	Options           map[string]interface{}
	Version           string
	TargetIPs         []string
	Discovery         network.DiscoveryOverrides
	ModuleConcurrency int
}

func parseAssessmentPayload(data map[string]interface{}) (assessmentJobPayload, error) {
	payload := assessmentJobPayload{
		Options: map[string]interface{}{},
	}

	if val, ok := data["assessmentId"].(string); ok && val != "" {
		payload.AssessmentID = val
	} else {
		return payload, fmt.Errorf("assessmentId missing in payload")
	}

	if modulesRaw, ok := data["modules"].([]interface{}); ok {
		for _, m := range modulesRaw {
			if s, ok := m.(string); ok {
				payload.Modules = append(payload.Modules, s)
			}
		}
	}

	if opts, ok := data["options"].(map[string]interface{}); ok {
		payload.Options = opts

		if subnetRaw, exists := opts["subnet"]; exists {
			targets, err := network.ParseSubnetOption(subnetRaw)
			if err != nil {
				return payload, fmt.Errorf("invalid subnet option: %w", err)
			}
			payload.TargetIPs = targets
		}

		if overridesRaw, exists := opts["discoveryOverrides"].(map[string]interface{}); exists {
			overrides, err := parseDiscoveryOverrides(overridesRaw)
			if err != nil {
				return payload, err
			}
			payload.Discovery = overrides
		}

		if concRaw, exists := opts["moduleConcurrency"]; exists {
			payload.ModuleConcurrency = parseIntOption(concRaw)
		}
	}

	if version, ok := data["version"].(string); ok {
		payload.Version = version
	}

	return payload, nil
}

func executeAssessmentJob(payload assessmentJobPayload, cfg *config.Config, log *logger.Logger) jobExecutionResult {
	modulesToRun := payload.Modules
	if len(modulesToRun) == 0 {
		modulesToRun = cfg.Assessment.DefaultModules
	}

	runner := modules.NewRunner(log, cfg.Assessment.Timeout)
	if len(payload.TargetIPs) == 0 {
		results, moduleErrors := runner.RunModules(modulesToRun)
		if len(moduleErrors) > 0 {
			log.Warn("Some modules reported errors", map[string]interface{}{"count": len(moduleErrors)})
		}

		overallRisk := calculateOverallRisk(results)
		summary := map[string]interface{}{
			"assessmentId":     payload.AssessmentID,
			"overallRiskScore": overallRisk,
			"resultCount":      len(results),
			"completedAt":      time.Now().UTC().Format(time.RFC3339),
			"modulesRequested": modulesToRun,
			"options":          payload.Options,
			"results":          convertResults(results),
			"riskBreakdown": map[string]int{
				modules.RiskLevelCritical: countByRiskLevel(results, modules.RiskLevelCritical),
				modules.RiskLevelHigh:     countByRiskLevel(results, modules.RiskLevelHigh),
				modules.RiskLevelMedium:   countByRiskLevel(results, modules.RiskLevelMedium),
				modules.RiskLevelLow:      countByRiskLevel(results, modules.RiskLevelLow),
			},
		}

		if len(moduleErrors) > 0 {
			summary["moduleErrors"] = stringifyModuleErrors(moduleErrors)
		}

		return jobExecutionResult{Status: jobStatusSucceeded, Summary: summary}
	}

	discoverer := network.NewDiscoverer(log)
	discoveryResult, err := discoverer.Discover(payload.TargetIPs, payload.Discovery)
	if err != nil {
		log.Error("Subnet discovery failed", map[string]interface{}{"error": err.Error()})
		return jobExecutionResult{
			Status:  jobStatusFailed,
			Summary: map[string]interface{}{"error": err.Error()},
		}
	}

	if len(discoveryResult.Active) == 0 {
		summary := map[string]interface{}{
			"assessmentId":     payload.AssessmentID,
			"modulesRequested": modulesToRun,
			"options":          payload.Options,
			"completedAt":      time.Now().UTC().Format(time.RFC3339),
			"overallRiskScore": 0.0,
			"resultCount":      0,
			"discoveredHosts":  []map[string]interface{}{},
			"unreachableHosts": discoveryResult.Unresponsive,
			"targets":          []map[string]interface{}{},
			"message":          "No responsive hosts discovered in subnet",
		}
		return jobExecutionResult{Status: jobStatusSucceeded, Summary: summary}
	}

	targetConcurrency := payload.ModuleConcurrency
	if targetConcurrency <= 0 {
		targetConcurrency = 4
	}
	if targetConcurrency > len(discoveryResult.Active) {
		targetConcurrency = len(discoveryResult.Active)
	}
	if targetConcurrency <= 0 {
		targetConcurrency = 1
	}

	type targetOutcome struct {
		host    network.TargetHost
		results []modules.AssessmentResult
		errors  []modules.ModuleExecutionError
	}

	jobs := make(chan network.TargetHost)
	outcomes := make(chan targetOutcome)

	var wg sync.WaitGroup
	for i := 0; i < targetConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				metadata := map[string]interface{}{"respondedBy": probeMethodsToStrings(host.RespondedBy)}
				ctx := modules.TargetContext{IP: host.IP, Metadata: metadata}
				res, moduleErrors := runner.RunModulesForTarget(modulesToRun, ctx)
				outcomes <- targetOutcome{host: host, results: res, errors: moduleErrors}
			}
		}()
	}

	go func() {
		for _, host := range discoveryResult.Active {
			jobs <- host
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(outcomes)
	}()

	aggregated := make([]modules.AssessmentResult, 0)
	targetSummaries := make([]map[string]interface{}, 0, len(discoveryResult.Active))
	var targetErrors []map[string]interface{}

	for outcome := range outcomes {
		aggregated = append(aggregated, outcome.results...)
		summaryEntry := map[string]interface{}{
			"targetIp":    outcome.host.IP,
			"respondedBy": probeMethodsToStrings(outcome.host.RespondedBy),
			"results":     convertResults(outcome.results),
		}

		if len(outcome.errors) > 0 {
			errs := stringifyModuleErrors(outcome.errors)
			summaryEntry["errors"] = errs
			targetErrors = append(targetErrors, map[string]interface{}{
				"targetIp": outcome.host.IP,
				"errors":   errs,
			})
		}

		targetSummaries = append(targetSummaries, summaryEntry)
	}

	sort.Slice(targetSummaries, func(i, j int) bool {
		return targetSummaries[i]["targetIp"].(string) < targetSummaries[j]["targetIp"].(string)
	})

	overallRisk := calculateOverallRisk(aggregated)
	summary := map[string]interface{}{
		"assessmentId":     payload.AssessmentID,
		"modulesRequested": modulesToRun,
		"options":          payload.Options,
		"completedAt":      time.Now().UTC().Format(time.RFC3339),
		"overallRiskScore": overallRisk,
		"resultCount":      len(aggregated),
		"targets":          targetSummaries,
		"discoveredHosts":  convertDiscoveredHosts(discoveryResult.Active),
		"unreachableHosts": discoveryResult.Unresponsive,
		"riskBreakdown": map[string]int{
			modules.RiskLevelCritical: countByRiskLevel(aggregated, modules.RiskLevelCritical),
			modules.RiskLevelHigh:     countByRiskLevel(aggregated, modules.RiskLevelHigh),
			modules.RiskLevelMedium:   countByRiskLevel(aggregated, modules.RiskLevelMedium),
			modules.RiskLevelLow:      countByRiskLevel(aggregated, modules.RiskLevelLow),
		},
	}

	if len(targetErrors) > 0 {
		summary["targetErrors"] = targetErrors
	}

	if len(discoveryResult.Unresponsive) > 0 {
		summary["unreachableCount"] = len(discoveryResult.Unresponsive)
	}

	return jobExecutionResult{Status: jobStatusSucceeded, Summary: summary}
}

func convertResults(results []modules.AssessmentResult) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(results))
	for _, r := range results {
		out = append(out, map[string]interface{}{
			"checkType":  r.CheckType,
			"riskScore":  r.RiskScore,
			"riskLevel":  r.RiskLevel,
			"data":       r.Data,
			"timestamp":  r.Timestamp.UTC().Format(time.RFC3339),
			"durationMs": r.Duration.Milliseconds(),
		})
	}
	return out
}

func stringifyModuleErrors(errs []modules.ModuleExecutionError) []string {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, e.Error())
	}
	return out
}

func probeMethodsToStrings(methods []network.ProbeMethod) []string {
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		out = append(out, string(m))
	}
	return out
}

func convertDiscoveredHosts(hosts []network.TargetHost) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, map[string]interface{}{
			"ip":          host.IP,
			"respondedBy": probeMethodsToStrings(host.RespondedBy),
		})
	}
	return out
}

func parseDiscoveryOverrides(raw map[string]interface{}) (network.DiscoveryOverrides, error) {
	overrides := network.DiscoveryOverrides{}

	if methodsRaw, ok := raw["methods"]; ok {
		methods, err := parseProbeMethods(methodsRaw)
		if err != nil {
			return overrides, err
		}
		overrides.Methods = methods
	}

	if concurrencyRaw, ok := raw["concurrency"]; ok {
		overrides.Concurrency = parseIntOption(concurrencyRaw)
	}

	if timeoutRaw, ok := raw["perHostTimeoutSeconds"]; ok {
		overrides.PerHostTimeout = time.Duration(parseIntOption(timeoutRaw)) * time.Second
	}

	if portsRaw, ok := raw["tcpPorts"]; ok {
		ports, err := parseIntSlice(portsRaw)
		if err != nil {
			return overrides, err
		}
		overrides.TCPPorts = ports
	}

	return overrides, nil
}

func parseProbeMethods(value interface{}) ([]network.ProbeMethod, error) {
	var items []string
	switch v := value.(type) {
	case []interface{}:
		for _, entry := range v {
			s, ok := entry.(string)
			if !ok {
				return nil, fmt.Errorf("probe methods must be strings, got %T", entry)
			}
			items = append(items, s)
		}
	case string:
		for _, part := range strings.Split(v, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				items = append(items, trimmed)
			}
		}
	default:
		return nil, fmt.Errorf("invalid probe methods type %T", value)
	}

	out := make([]network.ProbeMethod, 0, len(items))
	for _, item := range items {
		upper := strings.ToUpper(item)
		switch upper {
		case string(network.ProbeARP), string(network.ProbeTCP), string(network.ProbeICMP):
			out = append(out, network.ProbeMethod(upper))
		default:
			return nil, fmt.Errorf("unsupported probe method %s", item)
		}
	}
	return out, nil
}

func parseIntSlice(value interface{}) ([]int, error) {
	switch v := value.(type) {
	case []interface{}:
		var out []int
		for _, entry := range v {
			out = append(out, parseIntOption(entry))
		}
		return out, nil
	case string:
		parts := strings.Split(v, ",")
		var out []int
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			num, err := strconv.Atoi(trimmed)
			if err != nil {
				return nil, fmt.Errorf("invalid integer %q", trimmed)
			}
			out = append(out, num)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported list type %T", value)
	}
}

func parseIntOption(value interface{}) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0
		}
		if num, err := strconv.Atoi(trimmed); err == nil {
			return num
		}
	}
	return 0
}

func increaseBackoff(current time.Duration) time.Duration {
	next := current * 2
	if next > 30*time.Second {
		next = 30 * time.Second
	}
	return next
}

func pruneDedupeCache(cache map[string]time.Time) {
	cutoff := time.Now().Add(-6 * time.Hour)
	for id, ts := range cache {
		if ts.Before(cutoff) {
			delete(cache, id)
		}
	}
}

func listAvailableModules() error {
	fmt.Println("Available Assessment Modules:")
	fmt.Println()

	moduleList := modules.GetAvailableModules()
	for _, module := range moduleList {
		fmt.Printf("  %s\n", module.Name)
		fmt.Printf("    Description: %s\n", module.Description)
		fmt.Printf("    Risk Level: %s\n", module.DefaultRiskLevel)
		fmt.Printf("    Platform: %s\n", module.Platform)
		fmt.Println()
	}

	return nil
}

func calculateOverallRisk(results []modules.AssessmentResult) float64 {
	if len(results) == 0 {
		return 0.0
	}

	total := 0.0
	for _, result := range results {
		total += result.RiskScore
	}

	return total / float64(len(results))
}

func countByRiskLevel(results []modules.AssessmentResult, level string) int {
	count := 0
	for _, result := range results {
		if strings.EqualFold(result.RiskLevel, level) {
			count++
		}
	}
	return count
}
