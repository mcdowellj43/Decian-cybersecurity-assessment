package cmd

import (
	"decian-agent/internal/client"
	"decian-agent/internal/config"
	"decian-agent/internal/logger"
	"fmt"

	"github.com/spf13/cobra"
)

// statusCmd represents the status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show agent status and connection to dashboard",
	Long: `Display the current status of the agent including:
- Registration status
- Connection to dashboard
- Recent assessment history
- Agent configuration`,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	// Initialize configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize logger
	log := logger.NewLogger(cfg.Logging.Verbose)

	fmt.Printf("Decian Agent Status\n")
	fmt.Printf("==================\n\n")

	// Agent Information
	fmt.Printf("Agent Information:\n")
	if cfg.Agent.ID != "" {
		fmt.Printf("  Status: ✅ Registered\n")
		fmt.Printf("  Agent ID: %s\n", cfg.Agent.ID)
		fmt.Printf("  Hostname: %s\n", cfg.Agent.Hostname)
		fmt.Printf("  Version: %s\n", cfg.Agent.Version)
	} else {
		fmt.Printf("  Status: ❌ Not Registered\n")
		fmt.Printf("  Run 'decian-agent register' to register with dashboard\n")
	}
	fmt.Println()

	// Dashboard Configuration
	fmt.Printf("Dashboard Configuration:\n")
	if cfg.Dashboard.URL != "" {
		fmt.Printf("  URL: %s\n", cfg.Dashboard.URL)
	} else {
		fmt.Printf("  URL: ❌ Not configured\n")
	}

	if cfg.Auth.Token != "" {
		fmt.Printf("  Authentication: ✅ Token configured\n")
	} else {
		fmt.Printf("  Authentication: ❌ Token not configured\n")
	}
	fmt.Println()

	// Test connection if agent is registered
	if cfg.Agent.ID != "" && cfg.Dashboard.URL != "" && cfg.Auth.Token != "" {
		fmt.Printf("Dashboard Connection:\n")
		dashboardClient := client.NewDashboardClient(cfg.Dashboard.URL, cfg.Auth.Token, log)

		agent, err := dashboardClient.GetAgentStatus(cfg.Agent.ID)
		if err != nil {
			fmt.Printf("  Status: ❌ Connection failed\n")
			fmt.Printf("  Error: %s\n", err.Error())
		} else {
			fmt.Printf("  Status: ✅ Connected\n")
			fmt.Printf("  Agent Status: %s\n", agent.Status)
			if agent.LastSeen != nil {
				fmt.Printf("  Last Seen: %s\n", agent.LastSeen.Format("2006-01-02 15:04:05"))
			}
		}
		fmt.Println()
	}

	// Assessment Configuration
	fmt.Printf("Assessment Configuration:\n")
	fmt.Printf("  Default Modules: %d configured\n", len(cfg.Assessment.DefaultModules))
	for _, module := range cfg.Assessment.DefaultModules {
		fmt.Printf("    - %s\n", module)
	}
	fmt.Printf("  Dry Run Mode: %t\n", cfg.Agent.DryRun)
	fmt.Println()

	// Configuration File
	fmt.Printf("Configuration:\n")
	if cfg.ConfigFile != "" {
		fmt.Printf("  Config File: %s\n", cfg.ConfigFile)
	} else {
		fmt.Printf("  Config File: Using defaults (no config file found)\n")
	}
	fmt.Printf("  Verbose Logging: %t\n", cfg.Logging.Verbose)

	return nil
}