package cmd

import (
	"decian-agent/internal/client"
	"decian-agent/internal/config"
	"decian-agent/internal/logger"
	"fmt"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show agent registration and connectivity status",
	RunE:  runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	log := logger.NewLogger(cfg.Logging.Verbose)

	fmt.Println("Decian Agent Status")
	fmt.Println("==================")
	fmt.Println()

	fmt.Println("Configuration:")
	if cfg.ConfigFile != "" {
		fmt.Printf("  Config File: %s\n", cfg.ConfigFile)
	} else {
		fmt.Println("  Config File: <not found>")
	}
	fmt.Printf("  Server URL: %s\n", nonEmpty(cfg.Server.URL, "<not configured>"))
	fmt.Printf("  Organization ID: %s\n", nonEmpty(cfg.Organization.ID, "<not configured>"))
	fmt.Println()

	fmt.Println("Agent Credentials:")
	if cfg.Agent.ID != "" {
		fmt.Printf("  Agent ID: %s\n", cfg.Agent.ID)
	} else {
		fmt.Println("  Agent ID: <not registered>")
	}
	if cfg.Agent.Secret != "" {
		fmt.Println("  Secret: ✅ stored")
	} else {
		fmt.Println("  Secret: ❌ missing")
	}
	fmt.Printf("  Hostname: %s\n", nonEmpty(cfg.Agent.Hostname, "<unknown>"))
	fmt.Printf("  Version: %s\n", nonEmpty(cfg.Agent.Version, "<unknown>"))
	fmt.Printf("  Capacity: %d\n", cfg.Agent.Capacity)
	fmt.Printf("  Labels: %v\n", cfg.Agent.Labels)
	fmt.Println()

	if cfg.Server.URL == "" || cfg.Agent.ID == "" || cfg.Agent.Secret == "" {
		fmt.Println("Connectivity check skipped: missing configuration")
		return nil
	}

	apiClient := client.NewAPIClient(cfg.Server.URL, log)
	token, err := apiClient.MintAgentToken(cfg.Agent.ID, cfg.Agent.Secret)
	if err != nil {
		fmt.Println("Connectivity: ❌ unable to mint agent token")
		fmt.Printf("  Error: %v\n", err)
		return nil
	}

	fmt.Println("Connectivity: ✅ agent credentials accepted")
	fmt.Printf("  Token expires in: %d seconds\n", token.ExpiresIn)
	return nil
}

func nonEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
