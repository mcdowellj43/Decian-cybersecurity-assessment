package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// registerCmd represents the register command
var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Deprecated alias for setup",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("⚠️  'decian-agent register' is deprecated. Forwarding to 'decian-agent setup'.")
		return runSetup(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(registerCmd)
}
