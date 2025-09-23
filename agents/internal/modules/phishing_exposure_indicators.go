package modules

import (
	"decian-agent/internal/logger"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// PhishingExposureIndicatorsModule implements phishing exposure assessment
type PhishingExposureIndicatorsModule struct {
	logger *logger.Logger
}

// NewPhishingExposureIndicatorsModule creates a new phishing exposure indicators module
func NewPhishingExposureIndicatorsModule(logger *logger.Logger) Module {
	return &PhishingExposureIndicatorsModule{
		logger: logger,
	}
}

// Info returns information about the module
func (m *PhishingExposureIndicatorsModule) Info() ModuleInfo {
	return ModuleInfo{
		Name:             "Phishing Exposure Indicators",
		Description:      "Detect browser configurations, email settings, and security features that increase phishing susceptibility",
		CheckType:        CheckTypePhishingExposureIndicators,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelHigh,
		RequiresAdmin:    false,
	}
}

// Validate checks if the module can run in the current environment
func (m *PhishingExposureIndicatorsModule) Validate() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("this module only runs on Windows")
	}
	return nil
}

// Execute runs the phishing exposure assessment
func (m *PhishingExposureIndicatorsModule) Execute() (*AssessmentResult, error) {
	m.logger.Info("Starting phishing exposure indicators assessment")

	result := &AssessmentResult{
		CheckType: CheckTypePhishingExposureIndicators,
		Data:      make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	var findings []map[string]interface{}
	riskScore := 0.0

	// Check browser security settings
	browserFindings, browserRisk := m.checkBrowserSecuritySettings()
	if len(browserFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Browser Security",
			"findings": browserFindings,
		})
		riskScore += browserRisk
	}

	// Check email client security
	emailFindings, emailRisk := m.checkEmailClientSecurity()
	if len(emailFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Email Security",
			"findings": emailFindings,
		})
		riskScore += emailRisk
	}

	// Check Windows security features
	windowsFindings, windowsRisk := m.checkWindowsSecurityFeatures()
	if len(windowsFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Windows Security",
			"findings": windowsFindings,
		})
		riskScore += windowsRisk
	}

	// Check download protection settings
	downloadFindings, downloadRisk := m.checkDownloadProtection()
	if len(downloadFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Download Protection",
			"findings": downloadFindings,
		})
		riskScore += downloadRisk
	}

	// Check for suspicious browser extensions
	extensionFindings, extensionRisk := m.checkBrowserExtensions()
	if len(extensionFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Browser Extensions",
			"findings": extensionFindings,
		})
		riskScore += extensionRisk
	}

	// Cap risk score at 100
	if riskScore > 100 {
		riskScore = 100
	}

	result.Data["findings"] = findings
	result.Data["total_issues"] = len(findings)
	result.RiskScore = riskScore
	result.RiskLevel = DetermineRiskLevel(riskScore)

	m.logger.Info("Phishing exposure indicators assessment completed", map[string]interface{}{
		"findings_count": len(findings),
		"risk_score":     riskScore,
		"risk_level":     result.RiskLevel,
	})

	return result, nil
}

// checkBrowserSecuritySettings checks browser security configurations
func (m *PhishingExposureIndicatorsModule) checkBrowserSecuritySettings() ([]string, float64) {
	var findings []string
	var risk float64

	// Check Internet Explorer security zones
	ieKey, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones`, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		defer ieKey.Close()

		zones, err := ieKey.ReadSubKeyNames(-1)
		if err == nil {
			for _, zone := range zones {
				zoneKey, err := registry.OpenKey(ieKey, zone, registry.QUERY_VALUE)
				if err == nil {
					defer zoneKey.Close()

					// Check zone security level
					currentLevel, _, err := zoneKey.GetIntegerValue("CurrentLevel")
					if err == nil {
						zoneName := m.getIEZoneName(zone)
						if currentLevel > 0x11000 { // Higher than High security
							findings = append(findings, fmt.Sprintf("Internet Explorer %s zone has low security level", zoneName))
							risk += 15.0
						}

						// Check specific dangerous settings
						scriptingEnabled, _, err := zoneKey.GetIntegerValue("1400") // Active scripting
						if err == nil && scriptingEnabled == 0 {
							findings = append(findings, fmt.Sprintf("Active scripting enabled in %s zone", zoneName))
							risk += 10.0
						}
					}
				}
			}
		}
	}

	// Check Chrome security settings (via registry)
	chromeKey, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\\Google\\Chrome`, registry.QUERY_VALUE)
	if err == nil {
		defer chromeKey.Close()
		findings = append(findings, "Chrome browser detected - check security settings manually")
		risk += 5.0
	}

	// Check Edge security settings
	edgeKey, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\\Microsoft\\Edge`, registry.QUERY_VALUE)
	if err == nil {
		defer edgeKey.Close()
		findings = append(findings, "Microsoft Edge detected - check security settings manually")
		risk += 5.0
	}

	return findings, risk
}

// getIEZoneName returns the friendly name for IE security zones
func (m *PhishingExposureIndicatorsModule) getIEZoneName(zone string) string {
	switch zone {
	case "0":
		return "My Computer"
	case "1":
		return "Local Intranet"
	case "2":
		return "Trusted Sites"
	case "3":
		return "Internet"
	case "4":
		return "Restricted Sites"
	default:
		return "Unknown"
	}
}

// checkEmailClientSecurity checks email client security settings
func (m *PhishingExposureIndicatorsModule) checkEmailClientSecurity() ([]string, float64) {
	var findings []string
	var risk float64

	// Check Outlook security settings
	outlookKey, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\\Microsoft\\Office\\16.0\\Outlook\\Security`, registry.QUERY_VALUE)
	if err == nil {
		defer outlookKey.Close()

		// Check attachment security level
		level1Remove, _, err := outlookKey.GetStringValue("Level1Remove")
		if err == nil && level1Remove != "" {
			findings = append(findings, "Outlook Level 1 attachment blocking has been modified")
			risk += 20.0
		}

		// Check macro security
		macroSecurity, _, err := outlookKey.GetIntegerValue("Level")
		if err == nil && macroSecurity < 3 {
			findings = append(findings, "Outlook macro security level is set below recommended (High)")
			risk += 25.0
		}

		// Check external content
		downloadExternalContent, _, err := outlookKey.GetIntegerValue("BlockExtContent")
		if err == nil && downloadExternalContent == 0 {
			findings = append(findings, "Outlook allows automatic download of external content")
			risk += 15.0
		}
	}

	// Check Windows Mail/Mail app settings
	mailKey, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Mail`, registry.QUERY_VALUE)
	if err == nil {
		defer mailKey.Close()
		findings = append(findings, "Windows Mail app detected - check security settings manually")
		risk += 5.0
	}

	return findings, risk
}

// checkWindowsSecurityFeatures checks Windows security features that protect against phishing
func (m *PhishingExposureIndicatorsModule) checkWindowsSecurityFeatures() ([]string, float64) {
	var findings []string
	var risk float64

	// Check Windows Defender SmartScreen
	smartScreenKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer`, registry.QUERY_VALUE)
	if err == nil {
		defer smartScreenKey.Close()

		smartScreenEnabled, _, err := smartScreenKey.GetStringValue("SmartScreenEnabled")
		if err == nil {
			if smartScreenEnabled == "Off" {
				findings = append(findings, "Windows Defender SmartScreen is disabled")
				risk += 30.0
			} else if smartScreenEnabled == "Warn" {
				findings = append(findings, "Windows Defender SmartScreen is set to warn only")
				risk += 15.0
			}
		}
	}

	// Check Windows Defender settings
	defenderKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows Defender`, registry.QUERY_VALUE)
	if err == nil {
		defer defenderKey.Close()

		// Check real-time protection
		realtimeKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection`, registry.QUERY_VALUE)
		if err == nil {
			defer realtimeKey.Close()

			realtimeEnabled, _, err := realtimeKey.GetIntegerValue("DisableRealtimeMonitoring")
			if err == nil && realtimeEnabled == 1 {
				findings = append(findings, "Windows Defender real-time protection is disabled")
				risk += 35.0
			}
		}
	}

	// Check UAC settings
	uacKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System`, registry.QUERY_VALUE)
	if err == nil {
		defer uacKey.Close()

		uacEnabled, _, err := uacKey.GetIntegerValue("EnableLUA")
		if err == nil && uacEnabled == 0 {
			findings = append(findings, "User Account Control (UAC) is disabled")
			risk += 25.0
		}

		// Check UAC prompt level
		promptLevel, _, err := uacKey.GetIntegerValue("ConsentPromptBehaviorUser")
		if err == nil && promptLevel == 0 {
			findings = append(findings, "UAC is set to never notify")
			risk += 20.0
		}
	}

	return findings, risk
}

// checkDownloadProtection checks file download protection settings
func (m *PhishingExposureIndicatorsModule) checkDownloadProtection() ([]string, float64) {
	var findings []string
	var risk float64

	// Check attachment manager settings
	attachmentKey, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments`, registry.QUERY_VALUE)
	if err == nil {
		defer attachmentKey.Close()

		// Check if attachment execution is allowed
		saveZoneInfo, _, err := attachmentKey.GetIntegerValue("SaveZoneInformation")
		if err == nil && saveZoneInfo == 1 {
			findings = append(findings, "Zone information is not saved for downloaded files")
			risk += 15.0
		}

		// Check scan with antivirus
		scanWithAntivirus, _, err := attachmentKey.GetIntegerValue("ScanWithAntiVirus")
		if err == nil && scanWithAntivirus == 3 {
			findings = append(findings, "Downloaded files are not scanned with antivirus")
			risk += 20.0
		}
	}

	// Check browser download settings
	userProfile := os.Getenv("USERPROFILE")
	if userProfile != "" {
		// Check for suspicious download locations
		downloadPaths := []string{
			filepath.Join(userProfile, "Downloads"),
			filepath.Join(userProfile, "Desktop"),
			"C:\\temp",
			"C:\\tmp",
		}

		for _, path := range downloadPaths {
			if stat, err := os.Stat(path); err == nil && stat.IsDir() {
				// Check for executable files in download directories
				filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
					if err != nil {
						return nil
					}

					if strings.HasSuffix(strings.ToLower(info.Name()), ".exe") ||
						strings.HasSuffix(strings.ToLower(info.Name()), ".scr") ||
						strings.HasSuffix(strings.ToLower(info.Name()), ".bat") ||
						strings.HasSuffix(strings.ToLower(info.Name()), ".cmd") {

						// Check if file is recent (within last 30 days)
						if time.Since(info.ModTime()) < 30*24*time.Hour {
							findings = append(findings, fmt.Sprintf("Recent executable download detected: %s", info.Name()))
							risk += 10.0
						}
					}
					return nil
				})
			}
		}
	}

	return findings, risk
}

// checkBrowserExtensions checks for suspicious browser extensions
func (m *PhishingExposureIndicatorsModule) checkBrowserExtensions() ([]string, float64) {
	var findings []string
	var risk float64

	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		return findings, risk
	}

	// Check Chrome extensions
	chromeExtPath := filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Extensions")
	if stat, err := os.Stat(chromeExtPath); err == nil && stat.IsDir() {
		extDirs, err := os.ReadDir(chromeExtPath)
		if err == nil {
			extCount := len(extDirs)
			if extCount > 20 {
				findings = append(findings, fmt.Sprintf("Chrome has %d extensions installed (high number may indicate risk)", extCount))
				risk += 15.0
			} else if extCount > 10 {
				findings = append(findings, fmt.Sprintf("Chrome has %d extensions installed", extCount))
				risk += 5.0
			}
		}
	}

	// Check Edge extensions
	edgeExtPath := filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Extensions")
	if stat, err := os.Stat(edgeExtPath); err == nil && stat.IsDir() {
		extDirs, err := os.ReadDir(edgeExtPath)
		if err == nil {
			extCount := len(extDirs)
			if extCount > 20 {
				findings = append(findings, fmt.Sprintf("Edge has %d extensions installed (high number may indicate risk)", extCount))
				risk += 15.0
			} else if extCount > 10 {
				findings = append(findings, fmt.Sprintf("Edge has %d extensions installed", extCount))
				risk += 5.0
			}
		}
	}

	// Check Firefox add-ons
	firefoxProfilePath := filepath.Join(userProfile, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
	if stat, err := os.Stat(firefoxProfilePath); err == nil && stat.IsDir() {
		filepath.Walk(firefoxProfilePath, func(path string, info os.FileInfo, err error) error {
			if strings.HasSuffix(info.Name(), "extensions.json") {
				findings = append(findings, "Firefox extensions detected - manual review recommended")
				risk += 5.0
				return filepath.SkipDir
			}
			return nil
		})
	}

	return findings, risk
}