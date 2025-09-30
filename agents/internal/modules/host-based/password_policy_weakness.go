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

// PasswordPolicyWeaknessModule implements password policy weakness assessment
type PasswordPolicyWeaknessModule struct {
	logger *logger.Logger
	modules.TargetAware
}

// NewPasswordPolicyWeaknessModule creates a new password policy weakness module
// This constructor is used by both the legacy system and the new plugin system
func NewPasswordPolicyWeaknessModule(logger *logger.Logger) modules.Module {
	return &PasswordPolicyWeaknessModule{
		logger: logger,
	}
}

// NewPasswordPolicyWeaknessModulePlugin creates a new instance for the plugin system
// This follows the plugin constructor pattern for auto-discovery
func NewPasswordPolicyWeaknessModulePlugin(logger *logger.Logger) modules.ModulePlugin {
	return &PasswordPolicyWeaknessModule{
		logger: logger,
	}
}

// init registers this module for auto-discovery
func init() {
	modules.RegisterPluginConstructor(modules.CheckTypePasswordPolicyWeakness, NewPasswordPolicyWeaknessModulePlugin)
}

// GetInfo returns information about the module (modules.ModulePlugin interface)
func (m *PasswordPolicyWeaknessModule) GetInfo() modules.ModuleInfo {
	return modules.ModuleInfo{
		Name:             "Password Policy Weakness",
		Description:      "Analyze domain and local password policies for compliance with security best practices",
		CheckType:        modules.CheckTypePasswordPolicyWeakness,
		Platform:         "windows",
		DefaultRiskLevel: modules.RiskLevelHigh,
		RequiresAdmin:    true,
		Category:         modules.CategoryHostBased,
	}
}

// Info returns information about the module (legacy modules.Module interface)
func (m *PasswordPolicyWeaknessModule) Info() modules.ModuleInfo {
	return m.GetInfo()
}

// Validate checks if the module can run in the current environment
func (m *PasswordPolicyWeaknessModule) Validate() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("this module only runs on Windows")
	}
	return nil
}

// Execute runs the password policy weakness assessment
func (m *PasswordPolicyWeaknessModule) Execute() (*modules.AssessmentResult, error) {
	m.logger.Info("Starting password policy weakness assessment")

	result := &modules.AssessmentResult{
		CheckType: modules.CheckTypePasswordPolicyWeakness,
		Data:      make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	var findings []map[string]interface{}
	riskScore := 0.0

	// Check local password policy
	localPolicyFindings, localPolicyRisk := m.checkLocalPasswordPolicy()
	if len(localPolicyFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Local Password Policy",
			"findings": localPolicyFindings,
		})
		riskScore += localPolicyRisk
	}

	// Check account lockout policy
	lockoutFindings, lockoutRisk := m.checkAccountLockoutPolicy()
	if len(lockoutFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Account Lockout Policy",
			"findings": lockoutFindings,
		})
		riskScore += lockoutRisk
	}

	// Check password complexity requirements
	complexityFindings, complexityRisk := m.checkPasswordComplexityPolicy()
	if len(complexityFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Password Complexity",
			"findings": complexityFindings,
		})
		riskScore += complexityRisk
	}

	// Check password aging policy
	agingFindings, agingRisk := m.checkPasswordAgingPolicy()
	if len(agingFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Password Aging",
			"findings": agingFindings,
		})
		riskScore += agingRisk
	}

	// Check fine-grained password policies (if applicable)
	fineGrainedFindings, fineGrainedRisk := m.checkFineGrainedPasswordPolicy()
	if len(fineGrainedFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Fine-Grained Password Policy",
			"findings": fineGrainedFindings,
		})
		riskScore += fineGrainedRisk
	}

	// Cap risk score at 100
	if riskScore > 100 {
		riskScore = 100
	}

	result.Data["findings"] = findings
	result.Data["total_issues"] = len(findings)
	result.RiskScore = riskScore
	result.RiskLevel = modules.DetermineRiskLevel(riskScore)

	m.logger.Info("Password policy weakness assessment completed", map[string]interface{}{
		"findings_count": len(findings),
		"risk_score":     riskScore,
		"risk_level":     result.RiskLevel,
	})

	return result, nil
}

// checkLocalPasswordPolicy analyzes local password policy settings
func (m *PasswordPolicyWeaknessModule) checkLocalPasswordPolicy() ([]string, float64) {
	var findings []string
	var risk float64

	// Check LSA policy settings
	lsaKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Control\\Lsa`, registry.QUERY_VALUE)
	if err == nil {
		defer lsaKey.Close()

		// Check if LM hash storage is enabled
		noLMHash, _, err := lsaKey.GetIntegerValue("NoLMHash")
		if err == nil && noLMHash == 0 {
			findings = append(findings, "LM hash storage is enabled (weak password hashing)")
			risk += 25.0
		}

		// Check NTLM authentication level
		lmCompatibilityLevel, _, err := lsaKey.GetIntegerValue("LmCompatibilityLevel")
		if err == nil {
			switch lmCompatibilityLevel {
			case 0, 1:
				findings = append(findings, "NTLM authentication level allows LM and NTLM (insecure)")
				risk += 30.0
			case 2:
				findings = append(findings, "NTLM authentication level allows NTLM only")
				risk += 20.0
			case 3:
				findings = append(findings, "NTLM authentication level allows NTLMv2 only")
				risk += 10.0
			case 4:
				findings = append(findings, "NTLM authentication level requires NTLMv2 and rejects LM")
				risk += 5.0
			case 5:
				findings = append(findings, "NTLM authentication level requires NTLMv2 and rejects LM/NTLM")
				// This is secure, no risk added
			}
		}

		// Check if blank passwords are restricted
		limitBlankPasswordUse, _, err := lsaKey.GetIntegerValue("LimitBlankPasswordUse")
		if err == nil && limitBlankPasswordUse == 0 {
			findings = append(findings, "Blank passwords are allowed for console logon")
			risk += 35.0
		}
	}

	// Check SAM password policy (simplified check)
	samKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SAM\\SAM\\Domains\\Account`, registry.QUERY_VALUE)
	if err == nil {
		defer samKey.Close()

		// The F value contains binary policy data that would need to be parsed
		// For a full implementation, you'd decode the binary structure
		findings = append(findings, "Password policy requires SAM database analysis for detailed settings")
		risk += 5.0
	}

	return findings, risk
}

// checkAccountLockoutPolicy analyzes account lockout policy settings
func (m *PasswordPolicyWeaknessModule) checkAccountLockoutPolicy() ([]string, float64) {
	var findings []string
	var risk float64

	// Check account lockout settings through LSA
	lsaKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Control\\Lsa`, registry.QUERY_VALUE)
	if err == nil {
		defer lsaKey.Close()

		// Check crash on audit fail (security indicator)
		crashOnAuditFail, _, err := lsaKey.GetIntegerValue("CrashOnAuditFail")
		if err == nil && crashOnAuditFail == 0 {
			findings = append(findings, "System does not crash on audit failure")
			risk += 8.0
		}

		// Check audit base objects
		auditBaseObjects, _, err := lsaKey.GetIntegerValue("AuditBaseObjects")
		if err == nil && auditBaseObjects == 0 {
			findings = append(findings, "Audit policy for base objects is disabled")
			risk += 10.0
		}
	}

	// Check security policy settings
	securityKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System`, registry.QUERY_VALUE)
	if err == nil {
		defer securityKey.Close()

		// Check if last username is displayed (information disclosure)
		dontDisplayLastUserName, _, err := securityKey.GetIntegerValue("DontDisplayLastUserName")
		if err == nil && dontDisplayLastUserName == 0 {
			findings = append(findings, "Last logged-on username is displayed at logon")
			risk += 8.0
		}

		// Check shutdown without logon
		shutdownWithoutLogon, _, err := securityKey.GetIntegerValue("ShutdownWithoutLogon")
		if err == nil && shutdownWithoutLogon == 1 {
			findings = append(findings, "System can be shut down without logging on")
			risk += 5.0
		}
	}

	// Note: Actual lockout threshold, duration, and reset timer are stored in binary format
	// in the SAM database and would require more complex parsing
	findings = append(findings, "Account lockout thresholds require SAM database analysis")

	return findings, risk
}

// checkPasswordComplexityPolicy analyzes password complexity requirements
func (m *PasswordPolicyWeaknessModule) checkPasswordComplexityPolicy() ([]string, float64) {
	var findings []string
	var risk float64

	// Check Group Policy settings for password complexity
	gpoKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System`, registry.QUERY_VALUE)
	if err == nil {
		defer gpoKey.Close()

		// Check various security-related policies that affect password security
		disableCAD, _, err := gpoKey.GetIntegerValue("DisableCAD")
		if err == nil && disableCAD == 1 {
			findings = append(findings, "Ctrl+Alt+Del requirement is disabled")
			risk += 10.0
		}

		// Check legal notice settings (security awareness indicator)
		legalNoticeCaption, _, err := gpoKey.GetStringValue("LegalNoticeCaption")
		if err != nil || legalNoticeCaption == "" {
			findings = append(findings, "No legal notice is configured for logon")
			risk += 5.0
		}
	}

	// Check specific password policy through local security policy
	lsaKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Control\\Lsa`, registry.QUERY_VALUE)
	if err == nil {
		defer lsaKey.Close()

		// Check if passwords must meet complexity requirements
		// This is typically stored in binary format in LSA secrets
		findings = append(findings, "Password complexity requirements analysis requires LSA secrets access")
		risk += 5.0
	}

	// Check for password filters (additional complexity requirements)
	passwordFiltersKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Control\\Lsa`, registry.QUERY_VALUE)
	if err == nil {
		defer passwordFiltersKey.Close()

		notificationPackages, _, err := passwordFiltersKey.GetStringValue("Notification Packages")
		if err == nil && notificationPackages != "" {
			findings = append(findings, fmt.Sprintf("Password notification packages: %s", notificationPackages))
		}
	}

	return findings, risk
}

// checkPasswordAgingPolicy analyzes password aging and expiration settings
func (m *PasswordPolicyWeaknessModule) checkPasswordAgingPolicy() ([]string, float64) {
	var findings []string
	var risk float64

	// Check if password never expires is commonly used
	// This would typically require user enumeration through Windows APIs
	// For now, check related policy settings

	// Check service account settings
	servicesKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Services`, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		defer servicesKey.Close()

		serviceNames, err := servicesKey.ReadSubKeyNames(-1)
		if err == nil {
			serviceAccountsWithCustomLogin := 0
			for _, serviceName := range serviceNames {
				serviceKey, err := registry.OpenKey(servicesKey, serviceName, registry.QUERY_VALUE)
				if err != nil {
					continue
				}

				objName, _, err := serviceKey.GetStringValue("ObjectName")
				if err == nil {
					// Check for domain or custom accounts (potential password never expires)
					if len(objName) > 0 && objName != "LocalSystem" && objName != "LocalService" && objName != "NetworkService" {
						if !strings.HasPrefix(objName, "NT AUTHORITY") && !strings.HasPrefix(objName, "NT SERVICE") {
							serviceAccountsWithCustomLogin++
						}
					}
				}
				serviceKey.Close()
			}

			if serviceAccountsWithCustomLogin > 10 {
				findings = append(findings, fmt.Sprintf("High number of services with custom accounts: %d (potential password never expires)", serviceAccountsWithCustomLogin))
				risk += 20.0
			} else if serviceAccountsWithCustomLogin > 0 {
				findings = append(findings, fmt.Sprintf("Services with custom accounts: %d", serviceAccountsWithCustomLogin))
				risk += 8.0
			}
		}
	}

	// Check auto-logon settings (indicates stored passwords)
	winlogonKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon`, registry.QUERY_VALUE)
	if err == nil {
		defer winlogonKey.Close()

		autoAdminLogon, _, err := winlogonKey.GetStringValue("AutoAdminLogon")
		if err == nil && autoAdminLogon == "1" {
			findings = append(findings, "Automatic administrator logon is enabled")
			risk += 25.0

			// Check if password is stored in registry
			_, _, err = winlogonKey.GetStringValue("DefaultPassword")
			if err == nil {
				findings = append(findings, "Auto-logon password is stored in registry")
				risk += 35.0
			}
		}
	}

	return findings, risk
}

// checkFineGrainedPasswordPolicy checks for fine-grained password policies (domain environments)
func (m *PasswordPolicyWeaknessModule) checkFineGrainedPasswordPolicy() ([]string, float64) {
	var findings []string
	var risk float64

	// Check if system is domain-joined
	computerNameKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName`, registry.QUERY_VALUE)
	if err == nil {
		defer computerNameKey.Close()

		computerName, _, err := computerNameKey.GetStringValue("ComputerName")
		if err == nil {
			findings = append(findings, fmt.Sprintf("Computer name: %s", computerName))
		}
	}

	// Check domain membership
	tcpipKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters`, registry.QUERY_VALUE)
	if err == nil {
		defer tcpipKey.Close()

		domain, _, err := tcpipKey.GetStringValue("Domain")
		if err == nil && domain != "" {
			findings = append(findings, fmt.Sprintf("Domain member: %s", domain))

			// If domain-joined, fine-grained password policies could be in effect
			findings = append(findings, "Domain membership detected - fine-grained password policies may apply")
			// This is informational, not necessarily a risk
		} else {
			findings = append(findings, "System is not domain-joined - local password policies apply")
			risk += 5.0 // Standalone systems rely entirely on local policies
		}
	}

	// Check Group Policy client settings
	gpcKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History`, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		defer gpcKey.Close()

		policies, err := gpcKey.ReadSubKeyNames(-1)
		if err == nil && len(policies) > 0 {
			findings = append(findings, fmt.Sprintf("Group Policy objects applied: %d", len(policies)))
		} else {
			findings = append(findings, "No Group Policy objects detected")
			risk += 10.0
		}
	}

	// Check last Group Policy update
	gpKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\State\\Machine`, registry.QUERY_VALUE)
	if err == nil {
		defer gpKey.Close()

		lastGPOTime, _, err := gpKey.GetStringValue("LastGPOTime")
		if err == nil {
			findings = append(findings, fmt.Sprintf("Last Group Policy update: %s", lastGPOTime))
		}
	}

	return findings, risk
}
