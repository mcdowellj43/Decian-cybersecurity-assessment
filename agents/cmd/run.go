package cmd

import (
	"decian-agent/internal/client"
	"decian-agent/internal/config"
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"fmt"

	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run security assessment modules",
	Long: `Run the configured security assessment modules and report
results to the dashboard.

This command will:
1. Load the agent configuration
2. Execute selected assessment modules
3. Collect and format results
4. Submit results to the dashboard (unless --dry-run is specified)`,
	RunE: runAssessment,
}

func init() {
	rootCmd.AddCommand(runCmd)

	// Add flags specific to run command
	runCmd.Flags().StringSliceP("modules", "m", []string{}, "Specific modules to run (default: all configured modules)")
	runCmd.Flags().Bool("list-modules", false, "List available assessment modules and exit")
	runCmd.Flags().IntP("timeout", "T", 300, "Timeout for assessment in seconds")
}

func runAssessment(cmd *cobra.Command, args []string) error {
	// Check if user wants to list modules
	listModules, _ := cmd.Flags().GetBool("list-modules")
	if listModules {
		return listAvailableModules()
	}

	// Initialize configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize logger
	log := logger.NewLogger(cfg.Logging.Verbose)

	// Validate agent registration
	if cfg.Agent.ID == "" {
		return fmt.Errorf("agent not registered. Run 'decian-agent register' first")
	}

	log.Info("Starting security assessment", map[string]interface{}{
		"agent_id": cfg.Agent.ID,
		"hostname": cfg.Agent.Hostname,
		"dry_run":  cfg.Agent.DryRun,
	})

	// Get modules to run
	selectedModules, _ := cmd.Flags().GetStringSlice("modules")
	if len(selectedModules) == 0 {
		selectedModules = cfg.Assessment.DefaultModules
	}

	timeout, _ := cmd.Flags().GetInt("timeout")

	// Initialize module runner
	runner := modules.NewRunner(log, timeout)

	// Execute assessment modules
	results, err := runner.RunModules(selectedModules)
	if err != nil {
		return fmt.Errorf("assessment failed: %w", err)
	}

	log.Info("Assessment completed", map[string]interface{}{
		"modules_executed": len(results),
		"total_checks":     len(results),
	})

	// Calculate overall risk score
	overallRisk := calculateOverallRisk(results)

	log.Info("Assessment results", map[string]interface{}{
		"overall_risk_score": overallRisk,
		"critical_issues":    countByRiskLevel(results, "CRITICAL"),
		"high_risk_issues":   countByRiskLevel(results, "HIGH"),
		"medium_risk_issues": countByRiskLevel(results, "MEDIUM"),
		"low_risk_issues":    countByRiskLevel(results, "LOW"),
	})

	// Submit results to dashboard (unless dry-run)
	if !cfg.Agent.DryRun {
		dashboardClient := client.NewDashboardClient(cfg.Dashboard.URL, cfg.Auth.Token, log)

		err = dashboardClient.SubmitResults(cfg.Agent.ID, results, overallRisk)
		if err != nil {
			return fmt.Errorf("failed to submit results to dashboard: %w", err)
		}

		log.Info("Results submitted to dashboard successfully")
		fmt.Printf("✅ Assessment completed and results submitted to dashboard\n")
	} else {
		fmt.Printf("🔍 Assessment completed (dry-run mode - results not submitted)\n")
	}

	fmt.Printf("   Overall Risk Score: %.1f\n", overallRisk)
	fmt.Printf("   Critical Issues: %d\n", countByRiskLevel(results, "CRITICAL"))
	fmt.Printf("   High Risk Issues: %d\n", countByRiskLevel(results, "HIGH"))
	fmt.Printf("   Medium Risk Issues: %d\n", countByRiskLevel(results, "MEDIUM"))
	fmt.Printf("   Low Risk Issues: %d\n", countByRiskLevel(results, "LOW"))

	return nil
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
		if result.RiskLevel == level {
			count++
		}
	}
	return count
}