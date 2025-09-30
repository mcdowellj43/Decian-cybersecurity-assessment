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

// ElevatedPermissionsReportModule implements elevated permissions assessment
type ElevatedPermissionsReportModule struct {
	logger *logger.Logger
	modules.TargetAware
}

// NewElevatedPermissionsReportModule creates a new elevated permissions report module
// This constructor is used by both the legacy system and the new plugin system
func NewElevatedPermissionsReportModule(logger *logger.Logger) modules.Module {
	return &ElevatedPermissionsReportModule{
		logger: logger,
	}
}

// NewElevatedPermissionsReportModulePlugin creates a new instance for the plugin system
// This follows the plugin constructor pattern for auto-discovery
func NewElevatedPermissionsReportModulePlugin(logger *logger.Logger) modules.ModulePlugin {
	return &ElevatedPermissionsReportModule{
		logger: logger,
	}
}

// init registers this module for auto-discovery
func init() {
	modules.RegisterPluginConstructor(modules.CheckTypeElevatedPermissionsReport, NewElevatedPermissionsReportModulePlugin)
}

// GetInfo returns information about the module (modules.ModulePlugin interface)
func (m *ElevatedPermissionsReportModule) GetInfo() modules.ModuleInfo {
	return modules.ModuleInfo{
		Name:             "Elevated Permissions Report",
		Description:      "Identify accounts with administrative privileges, service accounts with high privileges, and privilege escalation risks",
		CheckType:        modules.CheckTypeElevatedPermissionsReport,
		Platform:         "windows",
		DefaultRiskLevel: modules.RiskLevelHigh,
		RequiresAdmin:    true,
		Category:         modules.CategoryHostBased,
	}
}

// Info returns information about the module (legacy modules.Module interface)
func (m *ElevatedPermissionsReportModule) Info() modules.ModuleInfo {
	return m.GetInfo()
}

// Validate checks if the module can run in the current environment
func (m *ElevatedPermissionsReportModule) Validate() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("this module only runs on Windows")
	}
	return nil
}

// Execute runs the elevated permissions assessment
func (m *ElevatedPermissionsReportModule) Execute() (*modules.AssessmentResult, error) {
	m.logger.Info("Starting elevated permissions assessment")

	result := &modules.AssessmentResult{
		CheckType: modules.CheckTypeElevatedPermissionsReport,
		Data:      make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	var findings []map[string]interface{}
	riskScore := 0.0

	// Check administrative accounts
	adminFindings, adminRisk := m.checkAdministrativeAccounts()
	if len(adminFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Administrative Accounts",
			"findings": adminFindings,
		})
		riskScore += adminRisk
	}

	// Check service account privileges
	serviceFindings, serviceRisk := m.checkServiceAccountPrivileges()
	if len(serviceFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Service Account Privileges",
			"findings": serviceFindings,
		})
		riskScore += serviceRisk
	}

	// Check privilege escalation risks
	escalationFindings, escalationRisk := m.checkPrivilegeEscalationRisks()
	if len(escalationFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Privilege Escalation Risks",
			"findings": escalationFindings,
		})
		riskScore += escalationRisk
	}

	// Check user rights assignments
	rightsFindings, rightsRisk := m.checkUserRightsAssignments()
	if len(rightsFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "User Rights Assignments",
			"findings": rightsFindings,
		})
		riskScore += rightsRisk
	}

	// Check local security policy
	policyFindings, policyRisk := m.checkLocalSecurityPolicy()
	if len(policyFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Security Policy",
			"findings": policyFindings,
		})
		riskScore += policyRisk
	}

	// Cap risk score at 100
	if riskScore > 100 {
		riskScore = 100
	}

	result.Data["findings"] = findings
	result.Data["total_issues"] = len(findings)
	result.RiskScore = riskScore
	result.RiskLevel = modules.DetermineRiskLevel(riskScore)

	m.logger.Info("Elevated permissions assessment completed", map[string]interface{}{
		"findings_count": len(findings),
		"risk_score":     riskScore,
		"risk_level":     result.RiskLevel,
	})

	return result, nil
}

// checkAdministrativeAccounts checks for administrative account configurations
func (m *ElevatedPermissionsReportModule) checkAdministrativeAccounts() ([]string, float64) {
	var findings []string
	var risk float64

	// Check built-in Administrator account status
	adminKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SAM\\SAM\\Domains\\Account\\Users\\000001F4`, registry.QUERY_VALUE)
	if err == nil {
		defer adminKey.Close()

		// Check if Administrator account is enabled
		f, _, err := adminKey.GetIntegerValue("F")
		if err == nil {
			// Administrator account enabled if bit 1 of F register is not set
			if f&0x0002 == 0 {
				findings = append(findings, "Built-in Administrator account is enabled")
				risk += 25.0
			}
		}
	}

	// Check for accounts in Administrators group through registry
	adminGroupKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SAM\\SAM\\Domains\\Builtin\\Aliases\\00000220\\Members`, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		defer adminGroupKey.Close()

		members, err := adminGroupKey.ReadSubKeyNames(-1)
		if err == nil {
			adminCount := len(members)
			if adminCount > 3 {
				findings = append(findings, fmt.Sprintf("High number of administrator accounts detected: %d", adminCount))
				risk += 15.0
			}
			findings = append(findings, fmt.Sprintf("Number of accounts in Administrators group: %d", adminCount))
		}
	}

	// Check Local Security Authority settings
	lsaKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Control\\Lsa`, registry.QUERY_VALUE)
	if err == nil {
		defer lsaKey.Close()

		// Check if "Run as administrator" is required
		filterAdminToken, _, err := lsaKey.GetIntegerValue("FilterAdministratorToken")
		if err == nil && filterAdminToken == 0 {
			findings = append(findings, "UAC Admin Approval Mode is disabled for built-in Administrator")
			risk += 20.0
		}

		// Check anonymous access restrictions
		restrictAnonymous, _, err := lsaKey.GetIntegerValue("RestrictAnonymous")
		if err == nil && restrictAnonymous == 0 {
			findings = append(findings, "Anonymous access is not restricted")
			risk += 15.0
		}
	}

	return findings, risk
}

// checkServiceAccountPrivileges checks service accounts for excessive privileges
func (m *ElevatedPermissionsReportModule) checkServiceAccountPrivileges() ([]string, float64) {
	var findings []string
	var risk float64

	// Check services running under high-privilege accounts
	servicesKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Services`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return findings, risk
	}
	defer servicesKey.Close()

	serviceNames, err := servicesKey.ReadSubKeyNames(-1)
	if err != nil {
		return findings, risk
	}

	privilegedServiceCount := 0
	customAccountCount := 0

	for _, serviceName := range serviceNames {
		serviceKey, err := registry.OpenKey(servicesKey, serviceName, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		// Check service account
		objName, _, err := serviceKey.GetStringValue("ObjectName")
		if err == nil {
			if strings.Contains(strings.ToLower(objName), "system") ||
				strings.Contains(strings.ToLower(objName), "administrator") {
				privilegedServiceCount++
			} else if strings.Contains(objName, "\\") && !strings.HasPrefix(objName, "NT ") {
				customAccountCount++
			}
		}

		// Check service type and start type for security implications
		serviceType, _, err := serviceKey.GetIntegerValue("Type")
		if err == nil && serviceType == 0x10 { // SERVICE_WIN32_OWN_PROCESS
			startType, _, err := serviceKey.GetIntegerValue("Start")
			if err == nil && startType == 2 { // SERVICE_AUTO_START
				// Check if this is a potentially risky auto-start service
				if strings.Contains(strings.ToLower(serviceName), "remote") ||
					strings.Contains(strings.ToLower(serviceName), "telnet") ||
					strings.Contains(strings.ToLower(serviceName), "ftp") {
					findings = append(findings, fmt.Sprintf("Potentially risky auto-start service: %s", serviceName))
					risk += 10.0
				}
			}
		}

		serviceKey.Close()
	}

	if privilegedServiceCount > 10 {
		findings = append(findings, fmt.Sprintf("High number of services running with system privileges: %d", privilegedServiceCount))
		risk += 15.0
	}

	if customAccountCount > 5 {
		findings = append(findings, fmt.Sprintf("Services running under custom accounts: %d", customAccountCount))
		risk += 10.0
	}

	return findings, risk
}

// checkPrivilegeEscalationRisks checks for common privilege escalation vectors
func (m *ElevatedPermissionsReportModule) checkPrivilegeEscalationRisks() ([]string, float64) {
	var findings []string
	var risk float64

	// Check UAC settings
	uacKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System`, registry.QUERY_VALUE)
	if err == nil {
		defer uacKey.Close()

		// Check if UAC is enabled
		enableLUA, _, err := uacKey.GetIntegerValue("EnableLUA")
		if err == nil && enableLUA == 0 {
			findings = append(findings, "User Account Control (UAC) is completely disabled")
			risk += 35.0
		}

		// Check UAC prompt behavior for administrators
		consentPromptBehaviorAdmin, _, err := uacKey.GetIntegerValue("ConsentPromptBehaviorAdmin")
		if err == nil && consentPromptBehaviorAdmin == 0 {
			findings = append(findings, "UAC is set to 'Never notify' for administrators")
			risk += 25.0
		}

		// Check UAC prompt behavior for standard users
		consentPromptBehaviorUser, _, err := uacKey.GetIntegerValue("ConsentPromptBehaviorUser")
		if err == nil && consentPromptBehaviorUser == 0 {
			findings = append(findings, "UAC automatically denies elevation requests for standard users")
			risk += 15.0
		}

		// Check if secure desktop is disabled
		promptOnSecureDesktop, _, err := uacKey.GetIntegerValue("PromptOnSecureDesktop")
		if err == nil && promptOnSecureDesktop == 0 {
			findings = append(findings, "UAC prompts do not run on secure desktop")
			risk += 10.0
		}
	}

	// Check Windows Error Reporting settings (can be used for privilege escalation)
	werKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting`, registry.QUERY_VALUE)
	if err == nil {
		defer werKey.Close()

		disabled, _, err := werKey.GetIntegerValue("Disabled")
		if err == nil && disabled == 0 {
			findings = append(findings, "Windows Error Reporting is enabled (potential privilege escalation vector)")
			risk += 5.0
		}
	}

	// Check for AlwaysInstallElevated policy
	alwaysElevatedMachine, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Policies\\Microsoft\\Windows\\Installer`, registry.QUERY_VALUE)
	if err == nil {
		defer alwaysElevatedMachine.Close()

		alwaysInstallElevated, _, err := alwaysElevatedMachine.GetIntegerValue("AlwaysInstallElevated")
		if err == nil && alwaysInstallElevated == 1 {
			findings = append(findings, "AlwaysInstallElevated policy is enabled (HIGH RISK privilege escalation)")
			risk += 40.0
		}
	}

	return findings, risk
}

// checkUserRightsAssignments checks user rights assignments for security risks
func (m *ElevatedPermissionsReportModule) checkUserRightsAssignments() ([]string, float64) {
	var findings []string
	var risk float64

	// Check critical user rights through LSA
	lsaKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Control\\Lsa`, registry.QUERY_VALUE)
	if err == nil {
		defer lsaKey.Close()

		// Check if "Act as part of the operating system" privilege is granted
		// This would require parsing binary LSA data, which is complex
		// For now, we'll check related settings

		// Check audit policy settings
		auditBaseObjects, _, err := lsaKey.GetIntegerValue("AuditBaseObjects")
		if err == nil && auditBaseObjects == 0 {
			findings = append(findings, "Audit policy for base objects is disabled")
			risk += 10.0
		}

		crashOnAuditFail, _, err := lsaKey.GetIntegerValue("CrashOnAuditFail")
		if err == nil && crashOnAuditFail == 0 {
			findings = append(findings, "System does not crash on audit failure")
			risk += 5.0
		}
	}

	// Check for dangerous scheduled tasks
	taskKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree`, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		defer taskKey.Close()

		tasks, err := taskKey.ReadSubKeyNames(-1)
		if err == nil {
			suspiciousTasks := 0
			for _, task := range tasks {
				if strings.Contains(strings.ToLower(task), "admin") ||
					strings.Contains(strings.ToLower(task), "elevated") ||
					strings.Contains(strings.ToLower(task), "system") {
					suspiciousTasks++
				}
			}

			if suspiciousTasks > 0 {
				findings = append(findings, fmt.Sprintf("Found %d potentially privileged scheduled tasks", suspiciousTasks))
				risk += float64(suspiciousTasks) * 5.0
			}
		}
	}

	return findings, risk
}

// checkLocalSecurityPolicy checks local security policy settings
func (m *ElevatedPermissionsReportModule) checkLocalSecurityPolicy() ([]string, float64) {
	var findings []string
	var risk float64

	// Check password policy settings
	accountKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SAM\\SAM\\Domains\\Account`, registry.QUERY_VALUE)
	if err == nil {
		defer accountKey.Close()

		// Note: The F value contains binary data that includes password policy
		// Parsing this requires understanding the SAM database format
		findings = append(findings, "Password policy analysis requires SAM database parsing")
		risk += 5.0
	}

	// Check LSA security settings
	lsaKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Control\\Lsa`, registry.QUERY_VALUE)
	if err == nil {
		defer lsaKey.Close()

		// Check LM hash storage
		noLMHash, _, err := lsaKey.GetIntegerValue("NoLMHash")
		if err == nil && noLMHash == 0 {
			findings = append(findings, "LM hash storage is enabled (weak password hashing)")
			risk += 20.0
		}

		// Check NTLM authentication level
		lmCompatibilityLevel, _, err := lsaKey.GetIntegerValue("LmCompatibilityLevel")
		if err == nil && lmCompatibilityLevel < 3 {
			findings = append(findings, "NTLM authentication level is set below recommended")
			risk += 15.0
		}

		// Check if null session shares are restricted
		restrictNullSessAccess, _, err := lsaKey.GetIntegerValue("RestrictNullSessAccess")
		if err == nil && restrictNullSessAccess == 0 {
			findings = append(findings, "Null session access to shares is not restricted")
			risk += 15.0
		}
	}

	// Check network security settings
	netSecKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0`, registry.QUERY_VALUE)
	if err == nil {
		defer netSecKey.Close()

		ntlmMinClientSec, _, err := netSecKey.GetIntegerValue("NtlmMinClientSec")
		if err == nil && ntlmMinClientSec < 0x20080000 {
			findings = append(findings, "NTLM minimum client security is set below recommended")
			risk += 10.0
		}
	}

	return findings, risk
}
