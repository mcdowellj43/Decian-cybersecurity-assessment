package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "decian-agent",
	Short: "Decian Cybersecurity Assessment Agent",
	Long: `A Windows security assessment agent that performs automated
security checks and reports results to the Decian dashboard.

The agent can perform various security assessments including:
- Windows Update status
- Firewall configuration
- PowerShell execution policies
- Account policies
- End-of-life software detection
- Network protocol security
- And many more security checks`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.decian-agent.yaml)")
        rootCmd.PersistentFlags().String("server", "", "Jobs API server URL")
        rootCmd.PersistentFlags().String("org-id", "", "Organization identifier")
        rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose logging")
        rootCmd.PersistentFlags().Bool("dry-run", false, "Run assessment without sending results to dashboard")

        // Bind flags to viper
        viper.BindPFlag("server.url", rootCmd.PersistentFlags().Lookup("server"))
        viper.BindPFlag("organization.id", rootCmd.PersistentFlags().Lookup("org-id"))
        viper.BindPFlag("logging.verbose", rootCmd.PersistentFlags().Lookup("verbose"))
        viper.BindPFlag("agent.dry_run", rootCmd.PersistentFlags().Lookup("dry-run"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".decian-agent" (without extension).
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".decian-agent")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}