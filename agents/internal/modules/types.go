package modules

import "time"

// AssessmentResult represents the result of a single assessment check
type AssessmentResult struct {
	CheckType string                 `json:"checkType"`
	RiskScore float64                `json:"riskScore"`
	RiskLevel string                 `json:"riskLevel"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
	Duration  time.Duration          `json:"duration"`
}

// ModuleInfo provides information about an assessment module
type ModuleInfo struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	CheckType        string `json:"checkType"`
	Platform         string `json:"platform"`
	DefaultRiskLevel string `json:"defaultRiskLevel"`
	RequiresAdmin    bool   `json:"requiresAdmin"`
	Category         string `json:"category"` // "host-based" or "network-based"
}

// ModulePlugin is the main interface that all assessment modules must implement
// This is the new plugin interface for dynamic module loading
type ModulePlugin interface {
	// GetInfo returns information about the module
	GetInfo() ModuleInfo

	// Execute runs the assessment and returns the result
	Execute() (*AssessmentResult, error)

	// Validate checks if the module can run in the current environment
	Validate() error
}

// Module interface that all assessment modules must implement
// This maintains backward compatibility with existing modules
type Module interface {
	ModulePlugin // Embed the new plugin interface

	// Info returns information about the module (legacy method)
	Info() ModuleInfo
}

// TargetContext represents metadata about the current execution target.
type TargetContext struct {
	IP       string
	Metadata map[string]interface{}
}

// TargetAwarePlugin is implemented by plugins that need to know the current target.
type TargetAwarePlugin interface {
	ModulePlugin
	SetTarget(TargetContext)
}

// ConfigurablePlugin is implemented by plugins that accept runtime configuration.
type ConfigurablePlugin interface {
	ModulePlugin
	Configure(config map[string]interface{}) error
}

// VersionedPlugin is implemented by plugins that provide version information.
type VersionedPlugin interface {
	ModulePlugin
	GetVersion() string
	GetCompatibilityVersion() string
}

// TargetAwareModule is implemented by modules that need to know the current target.
// This maintains backward compatibility with existing modules
type TargetAwareModule interface {
	Module
	SetTarget(TargetContext)
}

// TargetAware provides a reusable TargetAwareModule implementation.
type TargetAware struct {
	target TargetContext
}

// SetTarget stores the current target context.
func (t *TargetAware) SetTarget(target TargetContext) {
	t.target = target
}

// Target returns the previously stored context.
func (t *TargetAware) Target() TargetContext {
	return t.target
}

// RiskLevel constants
const (
	RiskLevelLow      = "LOW"
	RiskLevelMedium   = "MEDIUM"
	RiskLevelHigh     = "HIGH"
	RiskLevelCritical = "CRITICAL"
)

// CheckType constants (security-focused modules)
const (
	// Host-based modules
	CheckTypeMisconfigurationDiscovery  = "MISCONFIGURATION_DISCOVERY"
	CheckTypeWeakPasswordDetection      = "WEAK_PASSWORD_DETECTION"
	CheckTypeDataExposureCheck          = "DATA_EXPOSURE_CHECK"
	CheckTypePhishingExposureIndicators = "PHISHING_EXPOSURE_INDICATORS"
	CheckTypePatchUpdateStatus          = "PATCH_UPDATE_STATUS"
	CheckTypeElevatedPermissionsReport  = "ELEVATED_PERMISSIONS_REPORT"
	CheckTypeExcessiveSharingRisks      = "EXCESSIVE_SHARING_RISKS"
	CheckTypePasswordPolicyWeakness     = "PASSWORD_POLICY_WEAKNESS"
	CheckTypeOpenServicePortID          = "OPEN_SERVICE_PORT_ID"
	CheckTypeUserBehaviorRiskSignals    = "USER_BEHAVIOR_RISK_SIGNALS"

	// Network-based modules
	CheckTypePortServiceDiscovery = "PORT_SERVICE_DISCOVERY"
	CheckTypeOSFingerprinting     = "OS_FINGERPRINTING"
	CheckTypeSMBShareDiscovery    = "SMB_SHARE_DISCOVERY"
	CheckTypeWebPortalDiscovery   = "WEB_PORTAL_DISCOVERY"
	CheckTypeTrafficVisibility    = "TRAFFIC_VISIBILITY"
	CheckTypeRemoteAccessExposure = "REMOTE_ACCESS_EXPOSURE"
	CheckTypeDNSHygieneCheck      = "DNS_HYGIENE_CHECK"
	CheckTypePrinterEnumeration   = "PRINTER_ENUMERATION"
	CheckTypeWeakProtocolDetect   = "WEAK_PROTOCOL_DETECTION"
	CheckTypeUnpatchedBanner      = "UNPATCHED_BANNER"
)

// Module Category constants
const (
	CategoryHostBased    = "host-based"
	CategoryNetworkBased = "network-based"
)

// CalculateRiskScore calculates a risk score based on findings
func CalculateRiskScore(criticalCount, highCount, mediumCount, lowCount int) float64 {
	// Weight different risk levels
	score := float64(criticalCount)*90 + float64(highCount)*70 + float64(mediumCount)*40 + float64(lowCount)*10

	// Normalize to 0-100 scale (assuming max 10 issues per category)
	maxPossibleScore := 10*90 + 10*70 + 10*40 + 10*10 // 2000
	normalizedScore := (score / float64(maxPossibleScore)) * 100

	// Cap at 100
	if normalizedScore > 100 {
		normalizedScore = 100
	}

	return normalizedScore
}

// DetermineRiskLevel determines risk level based on score
func DetermineRiskLevel(score float64) string {
	switch {
	case score >= 90:
		return RiskLevelCritical
	case score >= 70:
		return RiskLevelHigh
	case score >= 40:
		return RiskLevelMedium
	default:
		return RiskLevelLow
	}
}
