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

// ExcessiveSharingRisksModule implements excessive sharing and collaboration risks assessment
type ExcessiveSharingRisksModule struct {
	logger *logger.Logger
	TargetAware
}

// NewExcessiveSharingRisksModule creates a new excessive sharing risks module
func NewExcessiveSharingRisksModule(logger *logger.Logger) Module {
	return &ExcessiveSharingRisksModule{
		logger: logger,
	}
}

// Info returns information about the module
func (m *ExcessiveSharingRisksModule) Info() ModuleInfo {
	return ModuleInfo{
		Name:             "Excessive Sharing & Collaboration Risks",
		Description:      "Analyze network shares, file permissions, cloud storage sync, and collaboration tool configurations for data exposure risks",
		CheckType:        CheckTypeExcessiveSharingRisks,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelMedium,
		RequiresAdmin:    true,
	}
}

// Validate checks if the module can run in the current environment
func (m *ExcessiveSharingRisksModule) Validate() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("this module only runs on Windows")
	}
	return nil
}

// Execute runs the excessive sharing risks assessment
func (m *ExcessiveSharingRisksModule) Execute() (*AssessmentResult, error) {
	m.logger.Info("Starting excessive sharing risks assessment")

	result := &AssessmentResult{
		CheckType: CheckTypeExcessiveSharingRisks,
		Data:      make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	var findings []map[string]interface{}
	riskScore := 0.0

	// Check network shares
	shareFindings, shareRisk := m.checkNetworkShares()
	if len(shareFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Network Shares",
			"findings": shareFindings,
		})
		riskScore += shareRisk
	}

	// Check file permissions
	permissionFindings, permissionRisk := m.checkFilePermissions()
	if len(permissionFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "File Permissions",
			"findings": permissionFindings,
		})
		riskScore += permissionRisk
	}

	// Check cloud storage synchronization
	cloudSyncFindings, cloudSyncRisk := m.checkCloudStorageSync()
	if len(cloudSyncFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Cloud Storage Sync",
			"findings": cloudSyncFindings,
		})
		riskScore += cloudSyncRisk
	}

	// Check collaboration tools
	collabFindings, collabRisk := m.checkCollaborationTools()
	if len(collabFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Collaboration Tools",
			"findings": collabFindings,
		})
		riskScore += collabRisk
	}

	// Check Windows sharing features
	windowsSharingFindings, windowsSharingRisk := m.checkWindowsSharingFeatures()
	if len(windowsSharingFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Windows Sharing Features",
			"findings": windowsSharingFindings,
		})
		riskScore += windowsSharingRisk
	}

	// Cap risk score at 100
	if riskScore > 100 {
		riskScore = 100
	}

	result.Data["findings"] = findings
	result.Data["total_issues"] = len(findings)
	result.RiskScore = riskScore
	result.RiskLevel = DetermineRiskLevel(riskScore)

	m.logger.Info("Excessive sharing risks assessment completed", map[string]interface{}{
		"findings_count": len(findings),
		"risk_score":     riskScore,
		"risk_level":     result.RiskLevel,
	})

	return result, nil
}

// checkNetworkShares analyzes network share configurations
func (m *ExcessiveSharingRisksModule) checkNetworkShares() ([]string, float64) {
	var findings []string
	var risk float64

	// Check SMB server configuration
	smbKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters`, registry.QUERY_VALUE)
	if err == nil {
		defer smbKey.Close()

		// Check if administrative shares are enabled
		autoShareWks, _, err := smbKey.GetIntegerValue("AutoShareWks")
		if err == nil && autoShareWks == 1 {
			findings = append(findings, "Administrative shares (C$, ADMIN$) are enabled")
			risk += 15.0
		}

		autoShareServer, _, err := smbKey.GetIntegerValue("AutoShareServer")
		if err == nil && autoShareServer == 1 {
			findings = append(findings, "Server administrative shares are enabled")
			risk += 15.0
		}

		// Check null session shares
		nullSessionShares, _, err := smbKey.GetStringValue("NullSessionShares")
		if err == nil && nullSessionShares != "" {
			shareList := strings.Split(nullSessionShares, "\x00")
			if len(shareList) > 1 {
				findings = append(findings, fmt.Sprintf("Null session shares configured: %v", shareList))
				risk += 25.0
			}
		}

		// Check SMB signing requirements
		requireSecuritySignature, _, err := smbKey.GetIntegerValue("RequireSecuritySignature")
		if err == nil && requireSecuritySignature == 0 {
			findings = append(findings, "SMB security signatures are not required")
			risk += 20.0
		}

		enableSecuritySignature, _, err := smbKey.GetIntegerValue("EnableSecuritySignature")
		if err == nil && enableSecuritySignature == 0 {
			findings = append(findings, "SMB security signatures are disabled")
			risk += 15.0
		}
	}

	// Check for specific shares in registry
	sharesKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares`, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		defer sharesKey.Close()

		shares, err := sharesKey.ReadSubKeyNames(-1)
		if err == nil {
			shareCount := 0
			for _, share := range shares {
				if !strings.HasSuffix(share, "$") { // Exclude administrative shares from count
					shareCount++
				}
			}

			if shareCount > 5 {
				findings = append(findings, fmt.Sprintf("High number of network shares detected: %d", shareCount))
				risk += 10.0
			}

			findings = append(findings, fmt.Sprintf("Total network shares found: %d", len(shares)))
		}
	}

	return findings, risk
}

// checkFilePermissions analyzes file and folder permissions
func (m *ExcessiveSharingRisksModule) checkFilePermissions() ([]string, float64) {
	var findings []string
	var risk float64

	// Check common sensitive directories for overly permissive access
	sensitivePaths := []string{
		"C:\\Windows\\System32",
		"C:\\Program Files",
		"C:\\Program Files (x86)",
		"C:\\Users",
	}

	for _, path := range sensitivePaths {
		if stat, err := os.Stat(path); err == nil && stat.IsDir() {
			// Basic check - in a full implementation, you'd analyze ACLs
			// For now, check if directories exist and are accessible
			findings = append(findings, fmt.Sprintf("Sensitive directory accessible: %s", path))
		}
	}

	// Check for files in public locations that might be overshared
	publicLocations := []string{
		"C:\\Users\\Public",
		"C:\\temp",
		"C:\\tmp",
	}

	for _, location := range publicLocations {
		if stat, err := os.Stat(location); err == nil && stat.IsDir() {
			fileCount := 0
			filepath.Walk(location, func(path string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() {
					fileCount++
				}
				return nil
			})

			if fileCount > 0 {
				findings = append(findings, fmt.Sprintf("Files found in public location %s: %d files", location, fileCount))
				if fileCount > 50 {
					risk += 15.0
				} else if fileCount > 10 {
					risk += 8.0
				} else {
					risk += 3.0
				}
			}
		}
	}

	// Check Windows file sharing settings
	networkKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Network\\LanMan`, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		defer networkKey.Close()

		shares, err := networkKey.ReadSubKeyNames(-1)
		if err == nil && len(shares) > 0 {
			findings = append(findings, fmt.Sprintf("Network shares configured in LanMan: %d", len(shares)))
			risk += 5.0
		}
	}

	return findings, risk
}

// checkCloudStorageSync analyzes cloud storage synchronization tools
func (m *ExcessiveSharingRisksModule) checkCloudStorageSync() ([]string, float64) {
	var findings []string
	var risk float64

	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		return findings, risk
	}

	// Check for cloud storage applications
	cloudStorageApps := map[string]string{
		"OneDrive":     filepath.Join(userProfile, "OneDrive"),
		"Dropbox":      filepath.Join(userProfile, "Dropbox"),
		"Google Drive": filepath.Join(userProfile, "Google Drive"),
		"Box":          filepath.Join(userProfile, "Box"),
		"iCloud":       filepath.Join(userProfile, "iCloudDrive"),
	}

	activeSyncApps := 0
	for appName, syncPath := range cloudStorageApps {
		if stat, err := os.Stat(syncPath); err == nil && stat.IsDir() {
			findings = append(findings, fmt.Sprintf("%s sync folder detected: %s", appName, syncPath))
			activeSyncApps++

			// Check for sensitive file types in sync folders
			sensitiveCount := 0
			filepath.Walk(syncPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}

				fileName := strings.ToLower(info.Name())
				if strings.HasSuffix(fileName, ".key") ||
					strings.HasSuffix(fileName, ".pem") ||
					strings.HasSuffix(fileName, ".p12") ||
					strings.HasSuffix(fileName, ".pfx") ||
					strings.HasSuffix(fileName, ".sql") ||
					strings.HasSuffix(fileName, ".bak") {
					sensitiveCount++
					if sensitiveCount <= 5 { // Limit reporting to avoid spam
						findings = append(findings, fmt.Sprintf("Sensitive file in %s sync: %s", appName, info.Name()))
					}
				}
				return nil
			})

			if sensitiveCount > 0 {
				risk += float64(sensitiveCount) * 8.0
			}
		}
	}

	if activeSyncApps > 2 {
		findings = append(findings, fmt.Sprintf("Multiple cloud sync applications detected: %d", activeSyncApps))
		risk += 10.0
	}

	// Check OneDrive registry settings
	oneDriveKey, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\\Microsoft\\OneDrive`, registry.QUERY_VALUE)
	if err == nil {
		defer oneDriveKey.Close()

		// Check if OneDrive Files On-Demand is enabled
		filesOnDemand, _, err := oneDriveKey.GetIntegerValue("EnableFileRecycleBin")
		if err == nil {
			findings = append(findings, fmt.Sprintf("OneDrive Files On-Demand setting: %d", filesOnDemand))
		}
	}

	return findings, risk
}

// checkCollaborationTools analyzes collaboration and communication tools
func (m *ExcessiveSharingRisksModule) checkCollaborationTools() ([]string, float64) {
	var findings []string
	var risk float64

	// Check for installed collaboration software
	uninstallKeys := []string{
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall`,
		`SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall`,
	}

	collaborationApps := []string{
		"microsoft teams", "slack", "discord", "zoom", "skype", "webex",
		"gotomeeting", "anydesk", "teamviewer", "chrome remote desktop",
		"sharepoint", "confluence", "jira", "trello", "asana", "notion",
	}

	installedCollabApps := 0

	for _, regPath := range uninstallKeys {
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
				lowerName := strings.ToLower(displayName)
				for _, collabApp := range collaborationApps {
					if strings.Contains(lowerName, collabApp) {
						findings = append(findings, fmt.Sprintf("Collaboration tool detected: %s", displayName))
						installedCollabApps++
						risk += 5.0
						break
					}
				}
			}
			appKey.Close()
		}
	}

	if installedCollabApps > 5 {
		findings = append(findings, fmt.Sprintf("High number of collaboration tools: %d", installedCollabApps))
		risk += 10.0
	}

	// Check for remote access tools specifically
	remoteAccessApps := []string{"teamviewer", "anydesk", "chrome remote desktop", "vnc", "rdp"}
	remoteAccessCount := 0

	for _, regPath := range uninstallKeys {
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
				lowerName := strings.ToLower(displayName)
				for _, remoteApp := range remoteAccessApps {
					if strings.Contains(lowerName, remoteApp) {
						findings = append(findings, fmt.Sprintf("Remote access tool detected: %s", displayName))
						remoteAccessCount++
						risk += 15.0
						break
					}
				}
			}
			appKey.Close()
		}
	}

	return findings, risk
}

// checkWindowsSharingFeatures analyzes Windows built-in sharing features
func (m *ExcessiveSharingRisksModule) checkWindowsSharingFeatures() ([]string, float64) {
	var findings []string
	var risk float64

	// Check HomeGroup settings (older Windows versions)
	homeGroupKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\HomeGroup`, registry.QUERY_VALUE)
	if err == nil {
		defer homeGroupKey.Close()
		findings = append(findings, "HomeGroup configuration detected")
		risk += 8.0
	}

	// Check Windows sharing wizard settings
	sharingWizardKey, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced`, registry.QUERY_VALUE)
	if err == nil {
		defer sharingWizardKey.Close()

		sharingWizardOn, _, err := sharingWizardKey.GetIntegerValue("SharingWizardOn")
		if err == nil && sharingWizardOn == 1 {
			findings = append(findings, "File sharing wizard is enabled")
			risk += 5.0
		}
	}

	// Check network discovery settings
	networkDiscoveryKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Control\\Network\\NewNetworkWindowOff`, registry.QUERY_VALUE)
	if err == nil {
		defer networkDiscoveryKey.Close()
		findings = append(findings, "Network discovery settings configured")
	}

	// Check for nearby sharing (Windows 10+)
	nearbySharingKey, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CDP`, registry.QUERY_VALUE)
	if err == nil {
		defer nearbySharingKey.Close()

		nearShareEnabled, _, err := nearbySharingKey.GetIntegerValue("NearShareChannelUserAuthzPolicy")
		if err == nil && nearShareEnabled != 0 {
			findings = append(findings, "Nearby sharing feature is configured")
			risk += 8.0
		}
	}

	// Check Windows Media Player sharing
	wmpSharingKey, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\\Microsoft\\MediaPlayer\\Preferences`, registry.QUERY_VALUE)
	if err == nil {
		defer wmpSharingKey.Close()

		mediaSharing, _, err := wmpSharingKey.GetIntegerValue("EnableMediaSharing")
		if err == nil && mediaSharing == 1 {
			findings = append(findings, "Windows Media Player sharing is enabled")
			risk += 10.0
		}
	}

	return findings, risk
}
