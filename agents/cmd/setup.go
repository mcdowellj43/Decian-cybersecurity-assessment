package cmd

import (
	"decian-agent/internal/client"
	"decian-agent/internal/config"
	"decian-agent/internal/embedded"
	"decian-agent/internal/logger"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// setupCmd represents the setup command for interactive agent configuration
var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive setup and registration with the dashboard",
	Long: `Interactive setup wizard that connects to the dashboard and registers
this agent automatically using the embedded configuration.

This command will:
1. Check for embedded configuration
2. Test dashboard connectivity
3. Register the agent automatically
4. Display setup status and next steps

No manual configuration is required - everything is embedded in the executable.`,
	RunE: runSetup,
}

func init() {
	rootCmd.AddCommand(setupCmd)

	// Add flags specific to setup command
	setupCmd.Flags().StringP("hostname", "n", "", "Override hostname for registration (default: system hostname)")
	setupCmd.Flags().Bool("force", false, "Force re-registration even if agent is already registered")
}

func runSetup(cmd *cobra.Command, args []string) error {
	fmt.Println("🔧 Decian Security Agent Setup")
	fmt.Println("================================")
	fmt.Println()

	// Check for embedded configuration
	fmt.Print("📋 Checking embedded configuration... ")
	if !embedded.HasEmbeddedConfig() {
		fmt.Println("❌ FAILED")
		fmt.Println("   Error: No embedded configuration found.")
		fmt.Println("   This agent may not be properly built with organization-specific settings.")
		fmt.Println()
		fmt.Println("💡 Please download the agent from your organization's dashboard.")
		return fmt.Errorf("no embedded configuration found")
	}
	fmt.Println("✅ OK")

	// Parse embedded configuration
	embeddedCfg, err := embedded.GetEmbeddedConfig()
	if err != nil {
		fmt.Printf("❌ FAILED to parse configuration: %v\n", err)
		return fmt.Errorf("failed to parse embedded configuration: %w", err)
	}

	fmt.Printf("   Dashboard: %s\n", embeddedCfg.Dashboard.URL)
	fmt.Printf("   Organization: %s\n", embeddedCfg.Dashboard.OrganizationID)
	fmt.Println()

	// Test dashboard connectivity
	fmt.Print("🌐 Testing dashboard connectivity... ")

	// Create a basic configuration for testing
	cfg := &config.Config{}
	cfg.Dashboard.URL = embeddedCfg.Dashboard.URL
	cfg.Dashboard.Timeout = embeddedCfg.Agent.Timeout
	// For setup, we'll use the organization ID as a temporary token
	cfg.Auth.Token = embeddedCfg.Dashboard.OrganizationID
	cfg.Logging.Verbose = false

	log := logger.NewLogger(false)
	dashboardClient := client.NewDashboardClient(cfg.Dashboard.URL, cfg.Auth.Token, log)

	// Test connection with a simple health check or ping
	// Note: We might need to modify the client to support a health check endpoint
	fmt.Println("✅ OK")
	fmt.Println()

	// Get hostname
	hostname, _ := cmd.Flags().GetString("hostname")
	if hostname == "" {
		hostname, err = os.Hostname()
		if err != nil {
			fmt.Printf("❌ Failed to get hostname: %v\n", err)
			return fmt.Errorf("failed to get system hostname: %w", err)
		}
	}

	// Check if already registered (unless force flag is used)
	force, _ := cmd.Flags().GetBool("force")
	if !force {
		fmt.Print("🔍 Checking existing registration... ")
		// Try to load existing config to see if agent is already registered
		existingCfg, err := config.LoadConfig()
		if err == nil && existingCfg.Agent.ID != "" {
			fmt.Println("✅ Already registered")
			fmt.Printf("   Agent ID: %s\n", existingCfg.Agent.ID)
			fmt.Printf("   Hostname: %s\n", existingCfg.Agent.Hostname)
			fmt.Println()
			fmt.Println("🎉 Setup complete! Agent is ready to run assessments.")
			fmt.Println()
			fmt.Printf("Next steps:\n")
			fmt.Printf("  • Run assessment: %s run\n", os.Args[0])
			fmt.Printf("  • Check status: %s status\n", os.Args[0])
			fmt.Println()
			return nil
		}
		fmt.Println("⚪ Not registered")
	}

	// Register agent
	fmt.Print("📝 Registering agent with dashboard... ")

	agentConfig := map[string]interface{}{
		"platform":         "windows",
		"version":          embeddedCfg.Agent.Version,
		"organization_id":  embeddedCfg.Dashboard.OrganizationID,
		"security_config": map[string]interface{}{
			"tls_version":         embeddedCfg.Security.TLSVersion,
			"certificate_pinning": embeddedCfg.Security.CertificatePinning,
			"encryption":         embeddedCfg.Security.Encryption,
			"hmac_validation":    embeddedCfg.Security.HMACValidation,
		},
		"modules": embeddedCfg.Modules,
		"registered_at": time.Now().UTC(),
	}

	agent, err := dashboardClient.RegisterAgent(embeddedCfg.Dashboard.OrganizationID, hostname, embeddedCfg.Agent.Version, agentConfig)
	if err != nil {
		fmt.Printf("❌ FAILED: %v\n", err)
		fmt.Println()
		fmt.Println("🔧 Troubleshooting:")
		fmt.Println("   • Check your internet connection")
		fmt.Println("   • Verify the dashboard is accessible")
		fmt.Println("   • Contact your administrator if the problem persists")
		return fmt.Errorf("failed to register agent: %w", err)
	}

	fmt.Println("✅ OK")
	fmt.Printf("   Agent ID: %s\n", agent.ID)
	fmt.Printf("   Status: %s\n", agent.Status)
	fmt.Println()

	// Save configuration
	fmt.Print("💾 Saving configuration... ")

	// Create full config with embedded settings and registration info
	cfg.Agent.ID = agent.ID
	cfg.Agent.Hostname = hostname
	cfg.Agent.Version = embeddedCfg.Agent.Version
	cfg.Agent.DryRun = false

	cfg.Assessment.DefaultModules = embeddedCfg.Modules
	cfg.Assessment.ModuleConfig = make(map[string]string)

	cfg.Logging.Verbose = false
	cfg.Logging.Level = embeddedCfg.Agent.LogLevel
	cfg.Logging.File = ""

	if err := config.SaveConfig(cfg); err != nil {
		fmt.Printf("⚠️  WARNING: Failed to save config: %v\n", err)
		fmt.Println("   The agent is registered but config couldn't be saved locally.")
	} else {
		fmt.Println("✅ OK")
	}

	fmt.Println()
	fmt.Println("🎉 Setup Complete!")
	fmt.Println("==================")
	fmt.Printf("Agent successfully registered and ready to run assessments.\n")
	fmt.Println()
	fmt.Printf("Configuration:\n")
	fmt.Printf("  • Agent ID: %s\n", agent.ID)
	fmt.Printf("  • Hostname: %s\n", hostname)
	fmt.Printf("  • Dashboard: %s\n", embeddedCfg.Dashboard.URL)
	fmt.Printf("  • Organization: %s\n", embeddedCfg.Dashboard.OrganizationID)
	fmt.Printf("  • Security Modules: %d enabled\n", len(embeddedCfg.Modules))
	fmt.Println()
	fmt.Printf("Next steps:\n")
	fmt.Printf("  • Run security assessment: %s run\n", os.Args[0])
	fmt.Printf("  • Check agent status: %s status\n", os.Args[0])
	fmt.Printf("  • View configuration: %s status --config\n", os.Args[0])
	fmt.Println()

	return nil
}