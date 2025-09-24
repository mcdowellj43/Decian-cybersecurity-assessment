package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config represents the agent configuration persisted on disk
type Config struct {
	ConfigFile   string             `yaml:"-"`
	Server       ServerConfig       `yaml:"server"`
	Organization OrganizationConfig `yaml:"organization"`
	Agent        AgentConfig        `yaml:"agent"`
	Auth         AuthConfig         `yaml:"auth"`
	Assessment   AssessmentConfig   `yaml:"assessment"`
	Logging      LoggingConfig      `yaml:"logging"`
}

type ServerConfig struct {
	URL string `yaml:"url"`
}

type OrganizationConfig struct {
	ID string `yaml:"id"`
}

type AgentConfig struct {
	ID       string            `yaml:"id"`
	Secret   string            `yaml:"secret"`
	Hostname string            `yaml:"hostname"`
	Version  string            `yaml:"version"`
	DryRun   bool              `yaml:"dry_run"`
	Capacity int               `yaml:"capacity"`
	Labels   map[string]string `yaml:"labels"`
}

type AuthConfig struct {
	AccessToken string `yaml:"access_token"`
	ExpiresAt   string `yaml:"expires_at"`
}

type AssessmentConfig struct {
	DefaultModules []string          `yaml:"default_modules"`
	ModuleConfig   map[string]string `yaml:"module_config"`
	Timeout        int               `yaml:"timeout"`
}

type LoggingConfig struct {
	Verbose bool   `yaml:"verbose"`
	Level   string `yaml:"level"`
	File    string `yaml:"file"`
}

// LoadConfig loads the configuration from file and environment
func LoadConfig() (*Config, error) {
	cfg := &Config{}

	setDefaults()

	cfg.ConfigFile = viper.ConfigFileUsed()
	cfg.Server.URL = viper.GetString("server.url")
	cfg.Organization.ID = viper.GetString("organization.id")

	cfg.Agent.ID = viper.GetString("agent.id")
	cfg.Agent.Secret = viper.GetString("agent.secret")
	cfg.Agent.Hostname = viper.GetString("agent.hostname")
	cfg.Agent.Version = viper.GetString("agent.version")
	cfg.Agent.DryRun = viper.GetBool("agent.dry_run")
	cfg.Agent.Capacity = viper.GetInt("agent.capacity")
	cfg.Agent.Labels = viper.GetStringMapString("agent.labels")

	cfg.Auth.AccessToken = viper.GetString("auth.access_token")
	cfg.Auth.ExpiresAt = viper.GetString("auth.expires_at")

	cfg.Assessment.DefaultModules = viper.GetStringSlice("assessment.default_modules")
	cfg.Assessment.ModuleConfig = viper.GetStringMapString("assessment.module_config")
	cfg.Assessment.Timeout = viper.GetInt("assessment.timeout")

	cfg.Logging.Verbose = viper.GetBool("logging.verbose")
	cfg.Logging.Level = viper.GetString("logging.level")
	cfg.Logging.File = viper.GetString("logging.file")

	return cfg, nil
}

// SaveConfig saves the current configuration to file
func SaveConfig(cfg *Config) error {
	configPath := cfg.ConfigFile
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		configPath = filepath.Join(home, ".decian-agent.yaml")
	}

	if cfg.Agent.Labels == nil {
		cfg.Agent.Labels = map[string]string{}
	}

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func setDefaults() {
	viper.SetDefault("server.url", "http://localhost:3001")
	viper.SetDefault("organization.id", "")

	viper.SetDefault("agent.version", "1.0.0")
	viper.SetDefault("agent.dry_run", false)
	viper.SetDefault("agent.capacity", 1)
	viper.SetDefault("agent.labels", map[string]string{})

	viper.SetDefault("assessment.timeout", 300)
	viper.SetDefault("assessment.default_modules", []string{
		"WIN_UPDATE_CHECK",
		"WIN_FIREWALL_STATUS_CHECK",
		"PSHELL_EXEC_POLICY_CHECK",
		"EOL_SOFTWARE_CHECK",
	})
	viper.SetDefault("assessment.module_config", map[string]string{})

	viper.SetDefault("logging.verbose", false)
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.file", "")
}
