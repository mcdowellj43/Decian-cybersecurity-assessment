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

// UserBehaviorRiskSignalsModule implements user behavior risk signals assessment
type UserBehaviorRiskSignalsModule struct {
	logger *logger.Logger
	TargetAware
}

// NewUserBehaviorRiskSignalsModule creates a new user behavior risk signals module
func NewUserBehaviorRiskSignalsModule(logger *logger.Logger) Module {
	return &UserBehaviorRiskSignalsModule{
		logger: logger,
	}
}

// Info returns information about the module
func (m *UserBehaviorRiskSignalsModule) Info() ModuleInfo {
	return ModuleInfo{
		Name:             "User Behavior Risk Signals",
		Description:      "Analyze user activity patterns, installed applications, browser usage, and system configurations for security risk indicators",
		CheckType:        CheckTypeUserBehaviorRiskSignals,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelMedium,
		RequiresAdmin:    false,
	}
}

// Validate checks if the module can run in the current environment
func (m *UserBehaviorRiskSignalsModule) Validate() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("this module only runs on Windows")
	}
	return nil
}

// Execute runs the user behavior risk signals assessment
func (m *UserBehaviorRiskSignalsModule) Execute() (*AssessmentResult, error) {
	m.logger.Info("Starting user behavior risk signals assessment")

	result := &AssessmentResult{
		CheckType: CheckTypeUserBehaviorRiskSignals,
		Data:      make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	var findings []map[string]interface{}
	riskScore := 0.0

	// Check browser usage patterns
	browserFindings, browserRisk := m.checkBrowserUsagePatterns()
	if len(browserFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Browser Usage",
			"findings": browserFindings,
		})
		riskScore += browserRisk
	}

	// Check installed applications
	appFindings, appRisk := m.checkInstalledApplications()
	if len(appFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Installed Applications",
			"findings": appFindings,
		})
		riskScore += appRisk
	}

	// Check user account behavior
	accountFindings, accountRisk := m.checkUserAccountBehavior()
	if len(accountFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "User Account Behavior",
			"findings": accountFindings,
		})
		riskScore += accountRisk
	}

	// Check file system activity
	filesystemFindings, filesystemRisk := m.checkFileSystemActivity()
	if len(filesystemFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "File System Activity",
			"findings": filesystemFindings,
		})
		riskScore += filesystemRisk
	}

	// Check system configuration changes
	configFindings, configRisk := m.checkSystemConfigurationChanges()
	if len(configFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "System Configuration",
			"findings": configFindings,
		})
		riskScore += configRisk
	}

	// Cap risk score at 100
	if riskScore > 100 {
		riskScore = 100
	}

	result.Data["findings"] = findings
	result.Data["total_issues"] = len(findings)
	result.RiskScore = riskScore
	result.RiskLevel = DetermineRiskLevel(riskScore)

	m.logger.Info("User behavior risk signals assessment completed", map[string]interface{}{
		"findings_count": len(findings),
		"risk_score":     riskScore,
		"risk_level":     result.RiskLevel,
	})

	return result, nil
}

// checkBrowserUsagePatterns analyzes browser usage for risk indicators
func (m *UserBehaviorRiskSignalsModule) checkBrowserUsagePatterns() ([]string, float64) {
	var findings []string
	var risk float64

	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		return findings, risk
	}

	// Check Chrome usage patterns
	chromeHistoryPath := filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "History")
	if _, err := os.Stat(chromeHistoryPath); err == nil {
		findings = append(findings, "Chrome browser usage detected")

		// Check for multiple Chrome profiles
		chromeProfilesPath := filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data")
		if entries, err := os.ReadDir(chromeProfilesPath); err == nil {
			profileCount := 0
			for _, entry := range entries {
				if entry.IsDir() && (strings.HasPrefix(entry.Name(), "Profile") || entry.Name() == "Default") {
					profileCount++
				}
			}
			if profileCount > 3 {
				findings = append(findings, fmt.Sprintf("Multiple Chrome profiles detected: %d", profileCount))
				risk += 8.0
			}
		}

		// Check Chrome preferences for risky settings
		chromePrefsPath := filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Preferences")
		if _, err := os.Stat(chromePrefsPath); err == nil {
			findings = append(findings, "Chrome preferences file found - manual analysis recommended for security settings")
			risk += 3.0
		}
	}

	// Check Firefox usage patterns
	firefoxProfilePath := filepath.Join(userProfile, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
	if stat, err := os.Stat(firefoxProfilePath); err == nil && stat.IsDir() {
		findings = append(findings, "Firefox browser usage detected")

		if entries, err := os.ReadDir(firefoxProfilePath); err == nil {
			profileCount := len(entries)
			if profileCount > 2 {
				findings = append(findings, fmt.Sprintf("Multiple Firefox profiles detected: %d", profileCount))
				risk += 8.0
			}
		}
	}

	// Check Edge usage patterns
	edgeHistoryPath := filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "History")
	if _, err := os.Stat(edgeHistoryPath); err == nil {
		findings = append(findings, "Microsoft Edge browser usage detected")
	}

	// Check for browsers with potential privacy/security risks
	riskyBrowserPaths := map[string]string{
		"Tor Browser": filepath.Join(userProfile, "Desktop", "Tor Browser"),
		"Opera":       filepath.Join(userProfile, "AppData", "Roaming", "Opera Software"),
		"Brave":       filepath.Join(userProfile, "AppData", "Local", "BraveSoftware"),
		"Vivaldi":     filepath.Join(userProfile, "AppData", "Local", "Vivaldi"),
	}

	for browserName, browserPath := range riskyBrowserPaths {
		if _, err := os.Stat(browserPath); err == nil {
			findings = append(findings, fmt.Sprintf("%s browser detected", browserName))
			if browserName == "Tor Browser" {
				risk += 15.0 // Tor can indicate privacy concerns or potential misuse
			} else {
				risk += 3.0
			}
		}
	}

	// Check for browser-related security tools
	if _, err := os.Stat(filepath.Join(userProfile, "AppData", "Local", "Mozilla", "Firefox", "Profiles")); err == nil {
		// Check for common Firefox security extensions (by looking for profile folders)
		findings = append(findings, "Firefox detected - check for security extensions manually")
	}

	return findings, risk
}

// checkInstalledApplications analyzes installed applications for risk indicators
func (m *UserBehaviorRiskSignalsModule) checkInstalledApplications() ([]string, float64) {
	var findings []string
	var risk float64

	// Check registry for installed applications
	uninstallKeys := []string{
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall`,
		`SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall`,
	}

	// Categories of potentially risky software
	riskyAppCategories := map[string][]string{
		"P2P/File Sharing": {
			"utorrent", "bittorrent", "emule", "limewire", "kazaa", "bearshare",
			"frostwire", "vuze", "deluge", "transmission",
		},
		"Remote Access": {
			"teamviewer", "anydesk", "logmein", "gotomypc", "chrome remote desktop",
			"vnc", "radmin", "ammyy", "supremo", "splashtop",
		},
		"Cracking/Hacking Tools": {
			"wireshark", "nmap", "metasploit", "burp suite", "john the ripper",
			"hashcat", "aircrack", "cain", "ophcrack", "rainbow crack",
		},
		"System Modification": {
			"cheat engine", "process hacker", "sysinternals", "hxd", "ollydbg",
			"ida pro", "x64dbg", "registry workshop", "ccleaner",
		},
		"Anonymous/Privacy Tools": {
			"tor", "proxifier", "psiphon", "hotspot shield", "nordvpn",
			"expressvpn", "windscribe", "protonvpn",
		},
		"Media/Entertainment": {
			"vlc", "kodi", "plex", "popcorn time", "stremio", "ace stream",
		},
	}

	installedApps := make(map[string]string)
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
				version, _, _ := appKey.GetStringValue("DisplayVersion")
				installedApps[displayName] = version
			}
			appKey.Close()
		}
	}

	// Analyze installed applications
	categoryRisks := make(map[string]int)
	for appName, version := range installedApps {
		lowerAppName := strings.ToLower(appName)

		for category, apps := range riskyAppCategories {
			for _, riskyApp := range apps {
				if strings.Contains(lowerAppName, riskyApp) {
					findings = append(findings, fmt.Sprintf("%s application detected: %s (%s)", category, appName, version))
					categoryRisks[category]++

					// Assign risk based on category
					switch category {
					case "Cracking/Hacking Tools":
						risk += 25.0
					case "Remote Access":
						risk += 15.0
					case "P2P/File Sharing":
						risk += 18.0
					case "System Modification":
						risk += 12.0
					case "Anonymous/Privacy Tools":
						risk += 10.0
					default:
						risk += 5.0
					}
					break
				}
			}
		}
	}

	// Additional risk for multiple risky categories
	if len(categoryRisks) > 3 {
		findings = append(findings, fmt.Sprintf("Multiple risky application categories detected: %d", len(categoryRisks)))
		risk += 15.0
	}

	findings = append(findings, fmt.Sprintf("Total applications installed: %d", len(installedApps)))

	return findings, risk
}

// checkUserAccountBehavior analyzes user account behavior patterns
func (m *UserBehaviorRiskSignalsModule) checkUserAccountBehavior() ([]string, float64) {
	var findings []string
	var risk float64

	// Check user profile settings
	userProfile := os.Getenv("USERPROFILE")
	if userProfile != "" {
		username := filepath.Base(userProfile)
		findings = append(findings, fmt.Sprintf("Current user profile: %s", username))

		// Check for multiple user profiles
		usersDir := filepath.Dir(userProfile)
		if entries, err := os.ReadDir(usersDir); err == nil {
			userCount := 0
			for _, entry := range entries {
				if entry.IsDir() && entry.Name() != "Public" && entry.Name() != "Default" {
					userCount++
				}
			}
			if userCount > 3 {
				findings = append(findings, fmt.Sprintf("Multiple user profiles detected: %d", userCount))
				risk += 8.0
			}
		}
	}

	// Check recent user activity through registry
	currentUserKey, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer`, registry.QUERY_VALUE)
	if err == nil {
		defer currentUserKey.Close()

		// Check for run MRU (Most Recently Used)
		runMRUKey, err := registry.OpenKey(registry.CURRENT_USER,
			`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU`, registry.ENUMERATE_SUB_KEYS)
		if err == nil {
			defer runMRUKey.Close()
			findings = append(findings, "Recent Run command history detected")
			risk += 5.0
		}
	}

	// Check Windows login events (simplified)
	eventLogKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security`, registry.QUERY_VALUE)
	if err == nil {
		defer eventLogKey.Close()

		maxSize, _, err := eventLogKey.GetIntegerValue("MaxSize")
		if err == nil && maxSize < 100*1024*1024 { // Less than 100MB
			findings = append(findings, "Security event log size is relatively small")
			risk += 8.0
		}
	}

	// Check user shell settings
	shellKey, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders`, registry.QUERY_VALUE)
	if err == nil {
		defer shellKey.Close()

		desktop, _, err := shellKey.GetStringValue("Desktop")
		if err == nil {
			// Check desktop for suspicious files
			if stat, err := os.Stat(desktop); err == nil && stat.IsDir() {
				if entries, err := os.ReadDir(desktop); err == nil {
					executableCount := 0
					for _, entry := range entries {
						if strings.HasSuffix(strings.ToLower(entry.Name()), ".exe") ||
							strings.HasSuffix(strings.ToLower(entry.Name()), ".bat") ||
							strings.HasSuffix(strings.ToLower(entry.Name()), ".cmd") {
							executableCount++
						}
					}
					if executableCount > 5 {
						findings = append(findings, fmt.Sprintf("Multiple executable files on desktop: %d", executableCount))
						risk += 10.0
					}
				}
			}
		}
	}

	return findings, risk
}

// checkFileSystemActivity analyzes file system activity for risk indicators
func (m *UserBehaviorRiskSignalsModule) checkFileSystemActivity() ([]string, float64) {
	var findings []string
	var risk float64

	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		return findings, risk
	}

	// Check Downloads folder for recent activity
	downloadsPath := filepath.Join(userProfile, "Downloads")
	if stat, err := os.Stat(downloadsPath); err == nil && stat.IsDir() {
		recentFiles := 0
		executableFiles := 0
		archiveFiles := 0

		filepath.Walk(downloadsPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			// Check for recent files (within last 30 days)
			if time.Since(info.ModTime()) < 30*24*time.Hour {
				recentFiles++

				fileName := strings.ToLower(info.Name())
				if strings.HasSuffix(fileName, ".exe") ||
					strings.HasSuffix(fileName, ".msi") ||
					strings.HasSuffix(fileName, ".bat") ||
					strings.HasSuffix(fileName, ".cmd") ||
					strings.HasSuffix(fileName, ".scr") {
					executableFiles++
				}

				if strings.HasSuffix(fileName, ".zip") ||
					strings.HasSuffix(fileName, ".rar") ||
					strings.HasSuffix(fileName, ".7z") ||
					strings.HasSuffix(fileName, ".tar") {
					archiveFiles++
				}
			}

			return nil
		})

		if recentFiles > 20 {
			findings = append(findings, fmt.Sprintf("High download activity: %d recent files", recentFiles))
			risk += 8.0
		}

		if executableFiles > 5 {
			findings = append(findings, fmt.Sprintf("Recent executable downloads: %d files", executableFiles))
			risk += 15.0
		}

		if archiveFiles > 10 {
			findings = append(findings, fmt.Sprintf("Recent archive downloads: %d files", archiveFiles))
			risk += 5.0
		}
	}

	// Check temporary directories for suspicious activity
	tempDirs := []string{
		os.Getenv("TEMP"),
		os.Getenv("TMP"),
		"C:\\temp",
		"C:\\tmp",
	}

	for _, tempDir := range tempDirs {
		if tempDir == "" {
			continue
		}

		if stat, err := os.Stat(tempDir); err == nil && stat.IsDir() {
			fileCount := 0
			filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() {
					fileCount++
				}
				return nil
			})

			if fileCount > 100 {
				findings = append(findings, fmt.Sprintf("High number of temporary files in %s: %d", tempDir, fileCount))
				risk += 8.0
			}
		}
	}

	return findings, risk
}

// checkSystemConfigurationChanges analyzes system configuration for user-made changes
func (m *UserBehaviorRiskSignalsModule) checkSystemConfigurationChanges() ([]string, float64) {
	var findings []string
	var risk float64

	// Check for modified system settings
	explorerKey, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced`, registry.QUERY_VALUE)
	if err == nil {
		defer explorerKey.Close()

		// Check if hidden files are shown
		hidden, _, err := explorerKey.GetIntegerValue("Hidden")
		if err == nil && hidden == 1 {
			findings = append(findings, "Hidden files and folders are set to be shown")
			risk += 5.0
		}

		// Check if file extensions are shown
		hideFileExt, _, err := explorerKey.GetIntegerValue("HideFileExt")
		if err == nil && hideFileExt == 0 {
			findings = append(findings, "File extensions are set to be shown")
			// This is actually good for security, no risk added
		}
	}

	// Check UAC settings
	uacKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System`, registry.QUERY_VALUE)
	if err == nil {
		defer uacKey.Close()

		enableLUA, _, err := uacKey.GetIntegerValue("EnableLUA")
		if err == nil && enableLUA == 0 {
			findings = append(findings, "User Account Control (UAC) is disabled")
			risk += 25.0
		}

		consentPromptBehaviorAdmin, _, err := uacKey.GetIntegerValue("ConsentPromptBehaviorAdmin")
		if err == nil && consentPromptBehaviorAdmin == 0 {
			findings = append(findings, "UAC is set to 'Never notify' for administrators")
			risk += 20.0
		}
	}

	// Check Windows Defender exclusions
	defenderKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows Defender\\Exclusions`, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		defer defenderKey.Close()

		exclusionTypes, err := defenderKey.ReadSubKeyNames(-1)
		if err == nil && len(exclusionTypes) > 0 {
			findings = append(findings, fmt.Sprintf("Windows Defender exclusions configured: %d types", len(exclusionTypes)))
			risk += 8.0
		}
	}

	// Check firewall status
	firewallKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile`, registry.QUERY_VALUE)
	if err == nil {
		defer firewallKey.Close()

		enableFirewall, _, err := firewallKey.GetIntegerValue("EnableFirewall")
		if err == nil && enableFirewall == 0 {
			findings = append(findings, "Windows Firewall is disabled")
			risk += 20.0
		}
	}

	return findings, risk
}
