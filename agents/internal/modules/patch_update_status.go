package modules

import (
	"decian-agent/internal/logger"
	"fmt"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// PatchUpdateStatusModule implements patch and update status assessment
type PatchUpdateStatusModule struct {
	logger *logger.Logger
}

// NewPatchUpdateStatusModule creates a new patch update status module
func NewPatchUpdateStatusModule(logger *logger.Logger) Module {
	return &PatchUpdateStatusModule{
		logger: logger,
	}
}

// Info returns information about the module
func (m *PatchUpdateStatusModule) Info() ModuleInfo {
	return ModuleInfo{
		Name:             "Patch & Update Status",
		Description:      "Evaluate Windows Update configuration, missing patches, and third-party software update status",
		CheckType:        CheckTypePatchUpdateStatus,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelHigh,
		RequiresAdmin:    true,
	}
}

// Validate checks if the module can run in the current environment
func (m *PatchUpdateStatusModule) Validate() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("this module only runs on Windows")
	}
	return nil
}

// Execute runs the patch update status assessment
func (m *PatchUpdateStatusModule) Execute() (*AssessmentResult, error) {
	m.logger.Info("Starting patch update status assessment")

	result := &AssessmentResult{
		CheckType: CheckTypePatchUpdateStatus,
		Data:      make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	var findings []map[string]interface{}
	riskScore := 0.0

	// Check Windows Update configuration
	wuConfigFindings, wuConfigRisk := m.checkWindowsUpdateConfiguration()
	if len(wuConfigFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Windows Update Configuration",
			"findings": wuConfigFindings,
		})
		riskScore += wuConfigRisk
	}

	// Check installed updates
	installedFindings, installedRisk := m.checkInstalledUpdates()
	if len(installedFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Installed Updates",
			"findings": installedFindings,
		})
		riskScore += installedRisk
	}

	// Check third-party software updates
	thirdPartyFindings, thirdPartyRisk := m.checkThirdPartySoftwareUpdates()
	if len(thirdPartyFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Third-Party Software",
			"findings": thirdPartyFindings,
		})
		riskScore += thirdPartyRisk
	}

	// Check Windows Defender definitions
	defenderFindings, defenderRisk := m.checkWindowsDefenderUpdates()
	if len(defenderFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Windows Defender",
			"findings": defenderFindings,
		})
		riskScore += defenderRisk
	}

	// Check automatic update settings
	autoUpdateFindings, autoUpdateRisk := m.checkAutomaticUpdateSettings()
	if len(autoUpdateFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Automatic Updates",
			"findings": autoUpdateFindings,
		})
		riskScore += autoUpdateRisk
	}

	// Cap risk score at 100
	if riskScore > 100 {
		riskScore = 100
	}

	result.Data["findings"] = findings
	result.Data["total_issues"] = len(findings)
	result.RiskScore = riskScore
	result.RiskLevel = DetermineRiskLevel(riskScore)

	m.logger.Info("Patch update status assessment completed", map[string]interface{}{
		"findings_count": len(findings),
		"risk_score":     riskScore,
		"risk_level":     result.RiskLevel,
	})

	return result, nil
}

// checkWindowsUpdateConfiguration checks Windows Update service configuration
func (m *PatchUpdateStatusModule) checkWindowsUpdateConfiguration() ([]string, float64) {
	var findings []string
	var risk float64

	// Check Windows Update service status
	wuKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update`, registry.QUERY_VALUE)
	if err == nil {
		defer wuKey.Close()

		// Check if automatic updates are enabled
		auOptions, _, err := wuKey.GetIntegerValue("AUOptions")
		if err == nil {
			switch auOptions {
			case 1:
				findings = append(findings, "Automatic Updates are disabled")
				risk += 40.0
			case 2:
				findings = append(findings, "Automatic Updates notify for download and install")
				risk += 20.0
			case 3:
				findings = append(findings, "Automatic Updates download and notify for install")
				risk += 10.0
			case 4:
				findings = append(findings, "Automatic Updates are fully automatic")
				// This is good, no risk added
			default:
				findings = append(findings, "Automatic Updates configuration is unknown")
				risk += 15.0
			}
		}

		// Check if updates are deferred
		deferUpgrade, _, err := wuKey.GetIntegerValue("DeferUpgrade")
		if err == nil && deferUpgrade == 1 {
			findings = append(findings, "Windows feature updates are deferred")
			risk += 10.0
		}
	}

	// Check Windows Update service
	servicesKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Services\\wuauserv`, registry.QUERY_VALUE)
	if err == nil {
		defer servicesKey.Close()

		start, _, err := servicesKey.GetIntegerValue("Start")
		if err == nil {
			switch start {
			case 2: // Automatic
				// Good configuration
			case 3: // Manual
				findings = append(findings, "Windows Update service is set to manual start")
				risk += 15.0
			case 4: // Disabled
				findings = append(findings, "Windows Update service is disabled")
				risk += 35.0
			}
		}
	}

	return findings, risk
}

// checkInstalledUpdates checks the status of installed Windows updates
func (m *PatchUpdateStatusModule) checkInstalledUpdates() ([]string, float64) {
	var findings []string
	var risk float64

	// Check Windows version and build
	versionKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion`, registry.QUERY_VALUE)
	if err == nil {
		defer versionKey.Close()

		currentBuild, _, err := versionKey.GetStringValue("CurrentBuild")
		if err == nil {
			findings = append(findings, fmt.Sprintf("Current Windows build: %s", currentBuild))

			// Check if build is relatively recent (this is a simplified check)
			// In production, you'd want to compare against known current builds
			buildNum := 0
			fmt.Sscanf(currentBuild, "%d", &buildNum)
			if buildNum < 19041 { // Windows 10 2004 or older
				findings = append(findings, "Windows build appears to be outdated")
				risk += 25.0
			}
		}

		releaseId, _, err := versionKey.GetStringValue("ReleaseId")
		if err == nil {
			findings = append(findings, fmt.Sprintf("Windows version: %s", releaseId))
		}

		ubr, _, err := versionKey.GetIntegerValue("UBR")
		if err == nil {
			findings = append(findings, fmt.Sprintf("Update Build Revision: %d", ubr))
		}
	}

	// Check last successful search time
	lastSearchKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Search`, registry.QUERY_VALUE)
	if err == nil {
		defer lastSearchKey.Close()

		lastSuccess, _, err := lastSearchKey.GetStringValue("LastSuccessTime")
		if err == nil {
			findings = append(findings, fmt.Sprintf("Last update search: %s", lastSuccess))
			// Parse the time and check if it's recent
			if lastTime, err := time.Parse("2006-01-02 15:04:05", lastSuccess); err == nil {
				if time.Since(lastTime) > 7*24*time.Hour {
					findings = append(findings, "Last update search was more than 7 days ago")
					risk += 15.0
				}
			}
		}
	}

	// Check pending reboot
	rebootKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired`, registry.QUERY_VALUE)
	if err == nil {
		defer rebootKey.Close()
		findings = append(findings, "System has pending updates requiring reboot")
		risk += 20.0
	}

	return findings, risk
}

// checkThirdPartySoftwareUpdates checks for outdated third-party software
func (m *PatchUpdateStatusModule) checkThirdPartySoftwareUpdates() ([]string, float64) {
	var findings []string
	var risk float64

	// Common software to check for updates
	_ = map[string]string{
		"Adobe Flash Player":     `SOFTWARE\\Macromedia\\FlashPlayer`,
		"Java":                   `SOFTWARE\\JavaSoft\\Java Runtime Environment`,
		"Adobe Reader":           `SOFTWARE\\Adobe\\Acrobat Reader`,
		"Google Chrome":          `SOFTWARE\\Google\\Chrome\\BLBeacon`,
		"Mozilla Firefox":        `SOFTWARE\\Mozilla\\Mozilla Firefox`,
		"VLC Media Player":       `SOFTWARE\\VideoLAN\\VLC`,
		"WinRAR":                 `SOFTWARE\\WinRAR`,
		"7-Zip":                  `SOFTWARE\\7-Zip`,
	}

	// Check installed software in both 32-bit and 64-bit registry hives
	registryPaths := []string{
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall`,
		`SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall`,
	}

	installedSoftware := make(map[string]string)

	for _, regPath := range registryPaths {
		uninstallKey, err := registry.OpenKey(registry.LOCAL_MACHINE, regPath, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		defer uninstallKey.Close()

		subkeys, err := uninstallKey.ReadSubKeyNames(-1)
		if err != nil {
			continue
		}

		for _, subkey := range subkeys {
			appKey, err := registry.OpenKey(uninstallKey, subkey, registry.QUERY_VALUE)
			if err != nil {
				continue
			}

			displayName, _, err := appKey.GetStringValue("DisplayName")
			if err == nil {
				version, _, err := appKey.GetStringValue("DisplayVersion")
				if err == nil {
					installedSoftware[displayName] = version
				}
			}
			appKey.Close()
		}
	}

	// Check for specific software versions
	for software, version := range installedSoftware {
		if strings.Contains(strings.ToLower(software), "flash") {
			findings = append(findings, fmt.Sprintf("Adobe Flash Player detected: %s (End-of-Life software)", version))
			risk += 30.0
		}
		if strings.Contains(strings.ToLower(software), "java") && strings.Contains(strings.ToLower(software), "runtime") {
			findings = append(findings, fmt.Sprintf("Java Runtime detected: %s (check for updates)", version))
			risk += 10.0
		}
		if strings.Contains(strings.ToLower(software), "adobe reader") {
			findings = append(findings, fmt.Sprintf("Adobe Reader detected: %s (check for updates)", version))
			risk += 8.0
		}
	}

	// Check for common vulnerable software patterns
	vulnerableSoftware := []string{
		"Internet Explorer",
		"Windows Media Player",
		"Silverlight",
	}

	for _, vulnSoft := range vulnerableSoftware {
		for software := range installedSoftware {
			if strings.Contains(strings.ToLower(software), strings.ToLower(vulnSoft)) {
				findings = append(findings, fmt.Sprintf("Potentially vulnerable software detected: %s", software))
				risk += 15.0
			}
		}
	}

	findings = append(findings, fmt.Sprintf("Found %d installed programs", len(installedSoftware)))

	return findings, risk
}

// checkWindowsDefenderUpdates checks Windows Defender signature updates
func (m *PatchUpdateStatusModule) checkWindowsDefenderUpdates() ([]string, float64) {
	var findings []string
	var risk float64

	// Check Windows Defender signature version
	defenderKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates`, registry.QUERY_VALUE)
	if err == nil {
		defer defenderKey.Close()

		// Check AV signature version
		avSignatureVersion, _, err := defenderKey.GetStringValue("AVSignatureVersion")
		if err == nil {
			findings = append(findings, fmt.Sprintf("Antivirus signature version: %s", avSignatureVersion))
		}

		// Check AS signature version
		asSignatureVersion, _, err := defenderKey.GetStringValue("ASSignatureVersion")
		if err == nil {
			findings = append(findings, fmt.Sprintf("Anti-spyware signature version: %s", asSignatureVersion))
		}

		// Check last update time
		lastUpdated, _, err := defenderKey.GetStringValue("AVSignatureUpdated")
		if err == nil {
			findings = append(findings, fmt.Sprintf("Last signature update: %s", lastUpdated))
			// Check if signatures are outdated (more than 3 days)
			if lastTime, err := time.Parse("2006-01-02 15:04:05", lastUpdated); err == nil {
				if time.Since(lastTime) > 3*24*time.Hour {
					findings = append(findings, "Windows Defender signatures are more than 3 days old")
					risk += 20.0
				}
			}
		}
	}

	// Check if Windows Defender is enabled
	realtimeKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection`, registry.QUERY_VALUE)
	if err == nil {
		defer realtimeKey.Close()

		realtimeEnabled, _, err := realtimeKey.GetIntegerValue("DisableRealtimeMonitoring")
		if err == nil && realtimeEnabled == 1 {
			findings = append(findings, "Windows Defender real-time protection is disabled")
			risk += 25.0
		}
	}

	return findings, risk
}

// checkAutomaticUpdateSettings checks various automatic update configurations
func (m *PatchUpdateStatusModule) checkAutomaticUpdateSettings() ([]string, float64) {
	var findings []string
	var risk float64

	// Check Windows Store app updates
	storeKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Policies\\Microsoft\\WindowsStore`, registry.QUERY_VALUE)
	if err == nil {
		defer storeKey.Close()

		autoDownload, _, err := storeKey.GetIntegerValue("AutoDownload")
		if err == nil && autoDownload == 2 {
			findings = append(findings, "Windows Store automatic app updates are disabled")
			risk += 10.0
		}
	}

	// Check Microsoft Update (for Office and other MS products)
	msUpdateKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Services`, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		defer msUpdateKey.Close()

		services, err := msUpdateKey.ReadSubKeyNames(-1)
		if err == nil {
			microsoftUpdateFound := false
			for _, service := range services {
				serviceKey, err := registry.OpenKey(msUpdateKey, service, registry.QUERY_VALUE)
				if err == nil {
					serviceName, _, err := serviceKey.GetStringValue("RegisteredWithAU")
					if err == nil && strings.Contains(serviceName, "Microsoft Update") {
						microsoftUpdateFound = true
					}
					serviceKey.Close()
				}
			}
			if !microsoftUpdateFound {
				findings = append(findings, "Microsoft Update service is not registered")
				risk += 15.0
			}
		}
	}

	// Check Group Policy settings that might affect updates
	policyKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU`, registry.QUERY_VALUE)
	if err == nil {
		defer policyKey.Close()

		noAutoUpdate, _, err := policyKey.GetIntegerValue("NoAutoUpdate")
		if err == nil && noAutoUpdate == 1 {
			findings = append(findings, "Automatic updates are disabled by Group Policy")
			risk += 30.0
		}

		auOptions, _, err := policyKey.GetIntegerValue("AUOptions")
		if err == nil && auOptions == 1 {
			findings = append(findings, "Group Policy disables automatic updates")
			risk += 30.0
		}
	}

	return findings, risk
}