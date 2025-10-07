package cmd

import (
	"encoding/json"
	"fmt"

	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"github.com/spf13/cobra"

	// Import modules for auto-registration
	_ "decian-agent/internal/modules/host-based"
	_ "decian-agent/internal/modules/network-based"
)

var modulesCmd = &cobra.Command{
	Use:   "modules",
	Short: "List available assessment modules",
	Long: `List all available assessment modules in either human-readable or JSON format.
This command is useful for discovering what security assessments this agent can perform.`,
	RunE: listModules,
}

func init() {
	rootCmd.AddCommand(modulesCmd)
	modulesCmd.Flags().Bool("json", false, "Output modules in JSON format")
}

func listModules(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	// Create a logger and runner to access the plugin manager
	// For JSON output, we need a silent logger to avoid corrupting the JSON
	log := logger.NewLogger(false)
	if jsonOutput {
		log = logger.NewSilentLogger()
	}
	runner := modules.NewRunner(log, 600) // 10 min timeout for module listing
	moduleList := runner.GetAvailableModulesFromPluginManager()

	if jsonOutput {
		return outputModulesJSON(moduleList)
	}

	return outputModulesHuman(moduleList)
}

func outputModulesJSON(moduleList []modules.ModuleInfo) error {
	// Create response structure that matches what the dashboard expects
	response := struct {
		Status string              `json:"status"`
		Data   []modules.ModuleInfo `json:"data"`
		Count  int                 `json:"count"`
	}{
		Status: "success",
		Data:   moduleList,
		Count:  len(moduleList),
	}

	output, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal modules to JSON: %w", err)
	}

	fmt.Println(string(output))
	return nil
}

func outputModulesHuman(moduleList []modules.ModuleInfo) error {
	fmt.Println("Available Assessment Modules:")
	fmt.Println()

	for _, module := range moduleList {
		fmt.Printf("  %s\n", module.Name)
		fmt.Printf("    Check Type: %s\n", module.CheckType)
		fmt.Printf("    Description: %s\n", module.Description)
		fmt.Printf("    Risk Level: %s\n", module.DefaultRiskLevel)
		fmt.Printf("    Platform: %s\n", module.Platform)
		fmt.Printf("    Requires Admin: %t\n", module.RequiresAdmin)
		fmt.Println()
	}

	fmt.Printf("Total modules available: %d\n", len(moduleList))
	return nil
}