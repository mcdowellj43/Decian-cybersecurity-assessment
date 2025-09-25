package cmd

import (
	"decian-agent/internal/client"
	"decian-agent/internal/config"
	"decian-agent/internal/logger"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive setup and registration with the Decian platform",
	Long: `Register the agent with the Decian platform using a one-time enrollment token.

This command will:
1. Validate the server URL and enrollment token
2. Register the agent and receive long-lived credentials
3. Persist the configuration for future runs`,
	RunE: runSetup,
}

func init() {
	rootCmd.AddCommand(setupCmd)

	setupCmd.Flags().String("server", "", "Decian API server URL")
	setupCmd.Flags().String("org-id", "", "Organization identifier")
	setupCmd.Flags().String("enroll-token", "", "One-time enrollment token")
	setupCmd.Flags().String("hostname", "", "Override hostname for registration")
	setupCmd.Flags().StringToString("labels", map[string]string{}, "Agent labels (key=value)")
	setupCmd.Flags().Int("capacity", 1, "Maximum concurrent jobs the agent will run")
	setupCmd.Flags().Bool("install-service", false, "Install the agent as a Windows service (optional)")
}

func runSetup(cmd *cobra.Command, args []string) error {
	fmt.Println("🔧 Decian Security Agent Setup")
	fmt.Println("================================")
	fmt.Println()

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	log := logger.NewLogger(viper.GetBool("logging.verbose"))

	server := valueOrFallback(cmd, "server", cfg.Server.URL)
	if server == "" {
		return fmt.Errorf("server URL is required (--server)")
	}

	orgID := valueOrFallback(cmd, "org-id", cfg.Organization.ID)
	if orgID == "" {
		return fmt.Errorf("organization ID is required (--org-id)")
	}

	enrollToken, _ := cmd.Flags().GetString("enroll-token")
	if enrollToken == "" {
		return fmt.Errorf("enrollment token is required (--enroll-token)")
	}

	labels, _ := cmd.Flags().GetStringToString("labels")
	if labels == nil {
		labels = map[string]string{}
	}

	capacity, _ := cmd.Flags().GetInt("capacity")
	if capacity <= 0 {
		capacity = 1
	}

	hostname, _ := cmd.Flags().GetString("hostname")
	if hostname == "" {
		hostname, err = os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to determine hostname: %w", err)
		}
	}

	version := cfg.Agent.Version
	if version == "" {
		version = viper.GetString("agent.version")
	}

	apiClient := client.NewAPIClient(server, log)
	resp, err := apiClient.RegisterAgent(client.RegisterRequest{
		OrgID:       orgID,
		Hostname:    hostname,
		Version:     version,
		EnrollToken: enrollToken,
		Labels:      labels,
	})
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	cfg.Server.URL = server
	cfg.Organization.ID = orgID
	cfg.Agent.ID = resp.AgentID
	cfg.Agent.Secret = resp.AgentSecret
	cfg.Agent.Hostname = hostname
	cfg.Agent.Version = version
	cfg.Agent.Capacity = capacity
	cfg.Agent.Labels = labels
	cfg.Agent.DryRun = viper.GetBool("agent.dry_run")
	cfg.Auth.AccessToken = ""
	cfg.Auth.ExpiresAt = ""

	if err := config.SaveConfig(cfg); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Println("✅ Agent registered successfully")
	fmt.Printf("   Agent ID: %s\n", resp.AgentID)
	fmt.Printf("   Server: %s\n", server)
	fmt.Printf("   Organization: %s\n", orgID)
	fmt.Printf("   Hostname: %s\n", hostname)
	fmt.Printf("   Labels: %v\n", labels)
	fmt.Println()

	installService, _ := cmd.Flags().GetBool("install-service")
	if installService {
		fmt.Println("⚠️  Service installation is not implemented in this build. Please install manually if required.")
	}

	fmt.Println("Next steps:")
	fmt.Printf("  • Run loop: %s run\n", os.Args[0])
	fmt.Printf("  • Check status: %s status\n", os.Args[0])
	fmt.Println()

	return nil
}

func valueOrFallback(cmd *cobra.Command, flagName string, fallback string) string {
	value, _ := cmd.Flags().GetString(flagName)
	if value != "" {
		return value
	}
	return fallback
}
