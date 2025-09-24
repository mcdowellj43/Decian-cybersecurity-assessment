package cmd

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"decian-agent/internal/client"
	"decian-agent/internal/config"
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
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
	AssessmentID string
	Modules      []string
	Options      map[string]interface{}
	Version      string
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
	results, err := runner.RunModules(modulesToRun)
	if err != nil {
		log.Error("Assessment execution failed", map[string]interface{}{"error": err.Error()})
		return jobExecutionResult{
			Status:  jobStatusFailed,
			Summary: map[string]interface{}{"error": err.Error()},
		}
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

	return jobExecutionResult{
		Status:  jobStatusSucceeded,
		Summary: summary,
	}
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
