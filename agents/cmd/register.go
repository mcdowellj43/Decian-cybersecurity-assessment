package cmd

import (
	"decian-agent/internal/client"
	"decian-agent/internal/config"
	"decian-agent/internal/logger"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// registerCmd represents the register command
var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register this agent with the dashboard",
	Long: `Register this agent with the Decian dashboard to enable
assessment management and result reporting.

This command will:
1. Validate the dashboard connection
2. Register the agent with hostname and version info
3. Save registration details to config file`,
	RunE: runRegister,
}

func init() {
	rootCmd.AddCommand(registerCmd)

	// Add flags specific to register command
	registerCmd.Flags().StringP("hostname", "n", "", "Override hostname for registration (default: system hostname)")
	registerCmd.Flags().String("version", "1.0.0", "Agent version")
}

func runRegister(cmd *cobra.Command, args []string) error {
	// Initialize configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize logger
	log := logger.NewLogger(cfg.Logging.Verbose)

	// Validate required configuration
	if cfg.Dashboard.URL == "" {
		return fmt.Errorf("dashboard URL is required. Set via --dashboard flag or config file")
	}

	if cfg.Auth.Token == "" {
		return fmt.Errorf("authentication token is required. Set via --token flag or config file")
	}

	// Get hostname override from flag
	hostname, _ := cmd.Flags().GetString("hostname")
	version, _ := cmd.Flags().GetString("version")

	if hostname == "" {
		hostname, err = os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get system hostname: %w", err)
		}
	}

	log.Info("Starting agent registration", map[string]interface{}{
		"hostname":     hostname,
		"version":      version,
		"dashboard":    cfg.Dashboard.URL,
	})

	// Create dashboard client
	dashboardClient := client.NewDashboardClient(cfg.Dashboard.URL, cfg.Auth.Token, log)

	// Register agent
	agent, err := dashboardClient.RegisterAgent(cfg.Dashboard.OrganizationID, hostname, version, map[string]interface{}{
		"platform":    "windows",
		"registered":  true,
	})
	if err != nil {
		return fmt.Errorf("failed to register agent: %w", err)
	}

	log.Info("Agent registered successfully", map[string]interface{}{
		"agent_id": agent.ID,
		"hostname": agent.Hostname,
		"status":   agent.Status,
	})

	// Save agent ID to config file
	cfg.Agent.ID = agent.ID
	cfg.Agent.Hostname = hostname
	cfg.Agent.Version = version

	if err := config.SaveConfig(cfg); err != nil {
		log.Warn("Failed to save agent ID to config file", map[string]interface{}{
			"error": err.Error(),
		})
	}

	fmt.Printf("✅ Agent registered successfully!\n")
	fmt.Printf("   Agent ID: %s\n", agent.ID)
	fmt.Printf("   Hostname: %s\n", agent.Hostname)
	fmt.Printf("   Status: %s\n", agent.Status)
	fmt.Printf("\nYou can now run assessments with: decian-agent run\n")

	return nil
}