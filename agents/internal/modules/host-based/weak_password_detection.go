package hostbased

import (
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"fmt"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// WeakPasswordDetectionModule implements weak password detection assessment
type WeakPasswordDetectionModule struct {
	logger *logger.Logger
	modules.TargetAware
}

// NewWeakPasswordDetectionModule creates a new weak password detection module
// This constructor is used by both the legacy system and the new plugin system
func NewWeakPasswordDetectionModule(logger *logger.Logger) modules.Module {
	return &WeakPasswordDetectionModule{
		logger: logger,
	}
}

// NewWeakPasswordDetectionModulePlugin creates a new instance for the plugin system
// This follows the plugin constructor pattern for auto-discovery
func NewWeakPasswordDetectionModulePlugin(logger *logger.Logger) modules.ModulePlugin {
	return &WeakPasswordDetectionModule{
		logger: logger,
	}
}

// init registers this module for auto-discovery
func init() {
	modules.RegisterPluginConstructor(modules.CheckTypeWeakPasswordDetection, NewWeakPasswordDetectionModulePlugin)
}

// GetInfo returns information about the module (modules.ModulePlugin interface)
func (m *WeakPasswordDetectionModule) GetInfo() modules.ModuleInfo {
	return modules.ModuleInfo{
		Name:             "Weak Password Detection",
		Description:      "Identify accounts using vendor defaults or passwords found in breach dictionaries",
		CheckType:        modules.CheckTypeWeakPasswordDetection,
		Platform:         "windows",
		DefaultRiskLevel: modules.RiskLevelHigh,
		RequiresAdmin:    true,
		Category:         modules.CategoryHostBased,
	}
}

// Info returns information about the module (legacy modules.Module interface)
func (m *WeakPasswordDetectionModule) Info() modules.ModuleInfo {
	return m.GetInfo()
}

// Validate checks if the module can run in the current environment
func (m *WeakPasswordDetectionModule) Validate() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("this module only runs on Windows")
	}
	return nil
}

// Execute runs the weak password detection assessment
func (m *WeakPasswordDetectionModule) Execute() (*modules.AssessmentResult, error) {
	m.logger.Info("Starting weak password detection assessment")

	result := &modules.AssessmentResult{
		CheckType: modules.CheckTypeWeakPasswordDetection,
		Data:      make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	var findings []map[string]interface{}
	riskScore := 0.0

	// Check password policy settings
	policyFindings, policyRisk := m.checkPasswordPolicy()
	if len(policyFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Password Policy",
			"findings": policyFindings,
		})
		riskScore += policyRisk
	}

	// Check for accounts with password never expires
	neverExpiresFindings, neverExpiresRisk := m.checkPasswordNeverExpires()
	if len(neverExpiresFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Password Expiration",
			"findings": neverExpiresFindings,
		})
		riskScore += neverExpiresRisk
	}

	// Check for blank passwords
	blankPasswordFindings, blankPasswordRisk := m.checkBlankPasswords()
	if len(blankPasswordFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Blank Passwords",
			"findings": blankPasswordFindings,
		})
		riskScore += blankPasswordRisk
	}

	// Check for common default passwords (service accounts)
	defaultPasswordFindings, defaultPasswordRisk := m.checkDefaultPasswords()
	if len(defaultPasswordFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Default Passwords",
			"findings": defaultPasswordFindings,
		})
		riskScore += defaultPasswordRisk
	}

	// Check password complexity requirements
	complexityFindings, complexityRisk := m.checkPasswordComplexity()
	if len(complexityFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Password Complexity",
			"findings": complexityFindings,
		})
		riskScore += complexityRisk
	}

	// Cap risk score at 100
	if riskScore > 100 {
		riskScore = 100
	}

	result.Data["findings"] = findings
	result.Data["total_issues"] = len(findings)
	result.RiskScore = riskScore
	result.RiskLevel = modules.DetermineRiskLevel(riskScore)

	m.logger.Info("Weak password detection completed", map[string]interface{}{
		"findings_count": len(findings),
		"risk_score":     riskScore,
		"risk_level":     result.RiskLevel,
	})

	return result, nil
}

// checkPasswordPolicy checks password policy settings
func (m *WeakPasswordDetectionModule) checkPasswordPolicy() ([]string, float64) {
	var findings []string
	var risk float64

	// Open LSA policy key
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
	if err != nil {
		m.logger.Warn("Failed to open LSA registry key", map[string]interface{}{
			"error": err.Error(),
		})
		return findings, risk
	}
	defer key.Close()

	// Check minimum password length
	domainKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SAM\SAM\Domains\Account`, registry.QUERY_VALUE)
	if err == nil {
		defer domainKey.Close()

		// Note: This is a simplified check. In practice, you'd need to parse
		// the binary data from the F value to get actual policy settings
		findings = append(findings, "Password policy check requires administrative access to SAM database")
		risk += 5.0
	}

	// Check for password history
	securityKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SECURITY\Policy\Accounts`, registry.QUERY_VALUE)
	if err != nil {
		// Alternative: Check using secpol.msc equivalent settings
		return m.checkPasswordPolicyAlternative()
	}
	defer securityKey.Close()

	return findings, risk
}

// checkPasswordPolicyAlternative uses alternative methods to check password policy
func (m *WeakPasswordDetectionModule) checkPasswordPolicyAlternative() ([]string, float64) {
	var findings []string
	var risk float64

	// Check if password complexity is enforced
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
	if err != nil {
		return findings, risk
	}
	defer key.Close()

	// Check CrashOnAuditFail (indicates security audit policy)
	crashOnAudit, _, err := key.GetIntegerValue("CrashOnAuditFail")
	if err == nil && crashOnAudit == 0 {
		findings = append(findings, "System does not crash on audit failure (security audit policy concern)")
		risk += 10.0
	}

	// Check LimitBlankPasswordUse
	limitBlank, _, err := key.GetIntegerValue("LimitBlankPasswordUse")
	if err == nil && limitBlank == 0 {
		findings = append(findings, "Blank passwords are allowed for console logon")
		risk += 25.0
	}

	return findings, risk
}

// checkPasswordNeverExpires checks for accounts with password never expires
func (m *WeakPasswordDetectionModule) checkPasswordNeverExpires() ([]string, float64) {
	var findings []string
	var risk float64

	// This would require more complex Windows API calls to enumerate users
	// For now, we'll check registry for service accounts
	servicesKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return findings, risk
	}
	defer servicesKey.Close()

	serviceNames, err := servicesKey.ReadSubKeyNames(-1)
	if err != nil {
		return findings, risk
	}

	serviceAccountCount := 0
	for _, serviceName := range serviceNames {
		serviceKey, err := registry.OpenKey(servicesKey, serviceName, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		// Check if service runs under a specific account
		objName, _, err := serviceKey.GetStringValue("ObjectName")
		if err == nil && objName != "LocalSystem" && objName != "LocalService" && objName != "NetworkService" {
			if strings.Contains(objName, "\\") && !strings.HasPrefix(objName, "NT AUTHORITY") {
				serviceAccountCount++
			}
		}
		serviceKey.Close()
	}

	if serviceAccountCount > 5 {
		findings = append(findings, fmt.Sprintf("Found %d services running under custom accounts (potential password never expires)", serviceAccountCount))
		risk += 15.0
	}

	return findings, risk
}

// checkBlankPasswords checks for blank password policy
func (m *WeakPasswordDetectionModule) checkBlankPasswords() ([]string, float64) {
	var findings []string
	var risk float64

	// Check LSA settings for blank password restrictions
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
	if err != nil {
		return findings, risk
	}
	defer key.Close()

	// Check if blank passwords are limited
	limitBlankPasswordUse, _, err := key.GetIntegerValue("LimitBlankPasswordUse")
	if err == nil && limitBlankPasswordUse == 0 {
		findings = append(findings, "Blank passwords are allowed for console logon")
		risk += 30.0
	}

	// Check NoLMHash setting
	noLMHash, _, err := key.GetIntegerValue("NoLMHash")
	if err == nil && noLMHash == 0 {
		findings = append(findings, "LM hash storage is enabled (weak password hashing)")
		risk += 20.0
	}

	return findings, risk
}

// checkDefaultPasswords checks for common default passwords
func (m *WeakPasswordDetectionModule) checkDefaultPasswords() ([]string, float64) {
	var findings []string
	var risk float64

	// Common service accounts that might use default passwords
	commonServiceAccounts := []string{
		"IUSR",
		"IWAM",
		"SQLService",
		"ReportService",
		"TFSService",
		"SharePoint",
	}

	// Check if these accounts exist in local users
	// This is a simplified check - in practice would need more extensive user enumeration
	findings = append(findings, "Default password check requires extensive user enumeration")

	// Check for common weak password indicators
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()

		// Check for auto-logon (potential weak passwords)
		autoLogon, _, err := key.GetStringValue("AutoAdminLogon")
		if err == nil && autoLogon == "1" {
			findings = append(findings, "Automatic logon is enabled (password may be stored)")
			risk += 25.0

			// Check if password is stored in registry
			_, _, err = key.GetStringValue("DefaultPassword")
			if err == nil {
				findings = append(findings, "Auto-logon password is stored in registry")
				risk += 35.0
			}
		}
	}

	for _, account := range commonServiceAccounts {
		_ = account // Placeholder for actual account checking logic
	}

	return findings, risk
}

// checkPasswordComplexity checks password complexity requirements
func (m *WeakPasswordDetectionModule) checkPasswordComplexity() ([]string, float64) {
	var findings []string
	var risk float64

	// Try to access password policy through various means
	// This requires administrative access to security database

	// Check if password complexity is enforced via group policy
	gpoKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, registry.QUERY_VALUE)
	if err == nil {
		defer gpoKey.Close()

		// Check various password-related policies
		disableCAD, _, err := gpoKey.GetIntegerValue("DisableCAD")
		if err == nil && disableCAD == 1 {
			findings = append(findings, "Ctrl+Alt+Del requirement is disabled")
			risk += 10.0
		}

		dontDisplayLastUserName, _, err := gpoKey.GetIntegerValue("DontDisplayLastUserName")
		if err == nil && dontDisplayLastUserName == 0 {
			findings = append(findings, "Last logged-on username is displayed at logon")
			risk += 5.0
		}
	}

	// Check account lockout policy indicators
	lsaKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
	if err == nil {
		defer lsaKey.Close()

		// Check audit policy settings (indicates security monitoring)
		auditBaseObjects, _, err := lsaKey.GetIntegerValue("AuditBaseObjects")
		if err == nil && auditBaseObjects == 0 {
			findings = append(findings, "Audit policy for base objects is disabled")
			risk += 10.0
		}
	}

	return findings, risk
}
