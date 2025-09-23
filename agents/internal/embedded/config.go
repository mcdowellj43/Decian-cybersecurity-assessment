package embedded

import (
	_ "embed"
	"fmt"
	"gopkg.in/yaml.v3"
)

// embeddedConfig holds the build-time configuration embedded in the executable
//go:embed agent-config.yaml
var embeddedConfigData string

// EmbeddedConfig represents the configuration embedded at build time
type EmbeddedConfig struct {
	Dashboard struct {
		URL            string `yaml:"url"`
		OrganizationID string `yaml:"organization_id"`
	} `yaml:"dashboard"`
	Agent struct {
		Version string `yaml:"version"`
		Timeout int    `yaml:"timeout"`
		LogLevel string `yaml:"log_level"`
	} `yaml:"agent"`
	Modules []string `yaml:"modules"`
	Security struct {
		TLSVersion         string `yaml:"tls_version"`
		CertificatePinning bool   `yaml:"certificate_pinning"`
		Encryption         bool   `yaml:"encryption"`
		HMACValidation     bool   `yaml:"hmac_validation"`
	} `yaml:"security"`
	Settings struct {
		RetryAttempts     int    `yaml:"retry_attempts"`
		RetryDelay        string `yaml:"retry_delay"`
		HeartbeatInterval string `yaml:"heartbeat_interval"`
	} `yaml:"settings"`
}

// GetEmbeddedConfig parses and returns the embedded configuration
func GetEmbeddedConfig() (*EmbeddedConfig, error) {
	if embeddedConfigData == "" {
		return nil, fmt.Errorf("no embedded configuration found - agent may not be properly built")
	}

	var config EmbeddedConfig
	if err := yaml.Unmarshal([]byte(embeddedConfigData), &config); err != nil {
		return nil, fmt.Errorf("failed to parse embedded configuration: %w", err)
	}

	return &config, nil
}

// HasEmbeddedConfig returns true if the executable has embedded configuration
func HasEmbeddedConfig() bool {
	return embeddedConfigData != ""
}

// GetEmbeddedConfigRaw returns the raw embedded configuration data
func GetEmbeddedConfigRaw() string {
	return embeddedConfigData
}