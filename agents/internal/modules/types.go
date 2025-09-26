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
}

// Module interface that all assessment modules must implement
type Module interface {
	// Info returns information about the module
	Info() ModuleInfo

	// Execute runs the assessment and returns the result
	Execute() (*AssessmentResult, error)

	// Validate checks if the module can run in the current environment
	Validate() error
}

// TargetContext represents metadata about the current execution target.
type TargetContext struct {
	IP       string
	Metadata map[string]interface{}
}

// TargetAwareModule is implemented by modules that need to know the current target.
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

// CheckType constants (new security-focused modules)
const (
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
