package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config represents the agent configuration
type Config struct {
	ConfigFile string `yaml:"-"`
	Agent      struct {
		ID       string `yaml:"id"`
		Hostname string `yaml:"hostname"`
		Version  string `yaml:"version"`
		DryRun   bool   `yaml:"dry_run"`
	} `yaml:"agent"`
	Dashboard struct {
		URL     string `yaml:"url"`
		Timeout int    `yaml:"timeout"`
	} `yaml:"dashboard"`
	Auth struct {
		Token string `yaml:"token"`
	} `yaml:"auth"`
	Assessment struct {
		DefaultModules []string          `yaml:"default_modules"`
		ModuleConfig   map[string]string `yaml:"module_config"`
	} `yaml:"assessment"`
	Logging struct {
		Verbose bool   `yaml:"verbose"`
		Level   string `yaml:"level"`
		File    string `yaml:"file"`
	} `yaml:"logging"`
}

// LoadConfig loads the configuration from file and environment
func LoadConfig() (*Config, error) {
	cfg := &Config{}

	// Set defaults
	setDefaults()

	// Load from viper (which includes config file, env vars, and flags)
	cfg.ConfigFile = viper.ConfigFileUsed()
	cfg.Agent.ID = viper.GetString("agent.id")
	cfg.Agent.Hostname = viper.GetString("agent.hostname")
	cfg.Agent.Version = viper.GetString("agent.version")
	cfg.Agent.DryRun = viper.GetBool("agent.dry_run")

	cfg.Dashboard.URL = viper.GetString("dashboard.url")
	cfg.Dashboard.Timeout = viper.GetInt("dashboard.timeout")

	cfg.Auth.Token = viper.GetString("auth.token")

	cfg.Assessment.DefaultModules = viper.GetStringSlice("assessment.default_modules")
	cfg.Assessment.ModuleConfig = viper.GetStringMapString("assessment.module_config")

	cfg.Logging.Verbose = viper.GetBool("logging.verbose")
	cfg.Logging.Level = viper.GetString("logging.level")
	cfg.Logging.File = viper.GetString("logging.file")

	return cfg, nil
}

// SaveConfig saves the current configuration to file
func SaveConfig(cfg *Config) error {
	// Determine config file path
	configPath := cfg.ConfigFile
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		configPath = filepath.Join(home, ".decian-agent.yaml")
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// setDefaults sets default configuration values
func setDefaults() {
	viper.SetDefault("agent.version", "1.0.0")
	viper.SetDefault("agent.dry_run", false)

	viper.SetDefault("dashboard.timeout", 30)

	viper.SetDefault("assessment.default_modules", []string{
		"WIN_UPDATE_CHECK",
		"WIN_FIREWALL_STATUS_CHECK",
		"PSHELL_EXEC_POLICY_CHECK",
		"EOL_SOFTWARE_CHECK",
	})

	viper.SetDefault("logging.verbose", false)
	viper.SetDefault("logging.level", "info")
}