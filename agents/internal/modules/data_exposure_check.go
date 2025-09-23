package modules

import (
	"decian-agent/internal/logger"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// DataExposureCheckModule implements data exposure assessment
type DataExposureCheckModule struct {
	logger *logger.Logger
}

// NewDataExposureCheckModule creates a new data exposure check module
func NewDataExposureCheckModule(logger *logger.Logger) Module {
	return &DataExposureCheckModule{
		logger: logger,
	}
}

// Info returns information about the module
func (m *DataExposureCheckModule) Info() ModuleInfo {
	return ModuleInfo{
		Name:             "Data Exposure Check",
		Description:      "Scan for exposed sensitive files, cloud storage misconfigurations, and unencrypted data stores",
		CheckType:        CheckTypeDataExposureCheck,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelHigh,
		RequiresAdmin:    true,
	}
}

// Validate checks if the module can run in the current environment
func (m *DataExposureCheckModule) Validate() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("this module only runs on Windows")
	}
	return nil
}

// Execute runs the data exposure assessment
func (m *DataExposureCheckModule) Execute() (*AssessmentResult, error) {
	m.logger.Info("Starting data exposure assessment")

	result := &AssessmentResult{
		CheckType: CheckTypeDataExposureCheck,
		Data:      make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	var findings []map[string]interface{}
	riskScore := 0.0

	// Check for exposed files with sensitive data
	exposedFilesFindings, exposedFilesRisk := m.checkExposedSensitiveFiles()
	if len(exposedFilesFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Exposed Files",
			"findings": exposedFilesFindings,
		})
		riskScore += exposedFilesRisk
	}

	// Check database configurations
	dbFindings, dbRisk := m.checkDatabaseExposure()
	if len(dbFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Database Exposure",
			"findings": dbFindings,
		})
		riskScore += dbRisk
	}

	// Check cloud storage configurations
	cloudFindings, cloudRisk := m.checkCloudStorageExposure()
	if len(cloudFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Cloud Storage",
			"findings": cloudFindings,
		})
		riskScore += cloudRisk
	}

	// Check browser saved credentials
	credentialsFindings, credentialsRisk := m.checkBrowserCredentials()
	if len(credentialsFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Browser Credentials",
			"findings": credentialsFindings,
		})
		riskScore += credentialsRisk
	}

	// Check email configurations
	emailFindings, emailRisk := m.checkEmailExposure()
	if len(emailFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Email Configuration",
			"findings": emailFindings,
		})
		riskScore += emailRisk
	}

	// Cap risk score at 100
	if riskScore > 100 {
		riskScore = 100
	}

	result.Data["findings"] = findings
	result.Data["total_issues"] = len(findings)
	result.RiskScore = riskScore
	result.RiskLevel = DetermineRiskLevel(riskScore)

	m.logger.Info("Data exposure assessment completed", map[string]interface{}{
		"findings_count": len(findings),
		"risk_score":     riskScore,
		"risk_level":     result.RiskLevel,
	})

	return result, nil
}

// checkExposedSensitiveFiles scans for files with sensitive extensions in common locations
func (m *DataExposureCheckModule) checkExposedSensitiveFiles() ([]string, float64) {
	var findings []string
	var risk float64

	// Sensitive file patterns to look for
	sensitivePatterns := []string{
		"*.key", "*.pem", "*.p12", "*.pfx", // Certificates and keys
		"*.sql", "*.bak", "*.backup",       // Database files
		"*.config", "*.ini", "*.conf",      // Configuration files
		"*.log",                            // Log files
		"*.csv", "*.xlsx",                  // Data exports
	}

	// Common exposed locations
	exposedLocations := []string{
		"C:\\",
		"C:\\Users\\Public",
		"C:\\temp",
		"C:\\tmp",
		"C:\\inetpub\\wwwroot",
	}

	for _, location := range exposedLocations {
		if _, err := os.Stat(location); os.IsNotExist(err) {
			continue
		}

		for _, pattern := range sensitivePatterns {
			matches, err := filepath.Glob(filepath.Join(location, pattern))
			if err != nil {
				continue
			}

			for _, match := range matches {
				// Check if file is in an exposed location
				if m.isFileExposed(match) {
					findings = append(findings, fmt.Sprintf("Sensitive file exposed: %s", match))
					risk += 15.0
				}
			}
		}
	}

	// Limit findings to avoid overwhelming output
	if len(findings) > 20 {
		findings = findings[:20]
		findings = append(findings, fmt.Sprintf("... and %d more files", len(findings)-20))
	}

	return findings, risk
}

// isFileExposed checks if a file is in a potentially exposed location
func (m *DataExposureCheckModule) isFileExposed(filePath string) bool {
	exposedPaths := []string{
		"C:\\inetpub\\wwwroot",
		"C:\\Users\\Public",
		"C:\\temp",
		"C:\\tmp",
		"C:\\",
	}

	for _, exposedPath := range exposedPaths {
		if strings.HasPrefix(strings.ToLower(filePath), strings.ToLower(exposedPath)) {
			return true
		}
	}
	return false
}

// checkDatabaseExposure checks for database configuration exposures
func (m *DataExposureCheckModule) checkDatabaseExposure() ([]string, float64) {
	var findings []string
	var risk float64

	// Check for SQL Server configurations
	sqlKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Microsoft SQL Server`, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		defer sqlKey.Close()

		// Check for SQL Server instances
		instances, err := sqlKey.ReadSubKeyNames(-1)
		if err == nil && len(instances) > 0 {
			findings = append(findings, fmt.Sprintf("Found %d SQL Server instances", len(instances)))
			risk += 10.0

			// Check for SQL Server authentication mode
			for _, instance := range instances {
				instanceKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
					fmt.Sprintf(`SOFTWARE\\Microsoft\\Microsoft SQL Server\\%s\\MSSQLServer`, instance), registry.QUERY_VALUE)
				if err == nil {
					defer instanceKey.Close()

					loginMode, _, err := instanceKey.GetIntegerValue("LoginMode")
					if err == nil && loginMode == 2 {
						findings = append(findings, fmt.Sprintf("SQL Server instance '%s' allows SQL authentication", instance))
						risk += 15.0
					}
				}
			}
		}
	}

	// Check for MySQL configurations
	mysqlKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\MySQL AB`, registry.QUERY_VALUE)
	if err == nil {
		defer mysqlKey.Close()
		findings = append(findings, "MySQL installation detected")
		risk += 5.0
	}

	return findings, risk
}

// checkCloudStorageExposure checks for cloud storage configuration exposures
func (m *DataExposureCheckModule) checkCloudStorageExposure() ([]string, float64) {
	var findings []string
	var risk float64

	// Common cloud storage credential locations
	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		return findings, risk
	}

	cloudCredentialPaths := []string{
		filepath.Join(userProfile, ".aws", "credentials"),
		filepath.Join(userProfile, ".azure", "credentials"),
		filepath.Join(userProfile, ".config", "gcloud"),
		filepath.Join(userProfile, "AppData", "Roaming", "Microsoft", "Azure"),
	}

	for _, credPath := range cloudCredentialPaths {
		if _, err := os.Stat(credPath); err == nil {
			findings = append(findings, fmt.Sprintf("Cloud credentials found: %s", filepath.Base(filepath.Dir(credPath))))
			risk += 20.0
		}
	}

	// Check for environment variables with cloud credentials
	envVars := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AZURE_CLIENT_ID",
		"AZURE_CLIENT_SECRET",
		"GOOGLE_APPLICATION_CREDENTIALS",
	}

	for _, envVar := range envVars {
		if value := os.Getenv(envVar); value != "" {
			findings = append(findings, fmt.Sprintf("Cloud credential in environment variable: %s", envVar))
			risk += 25.0
		}
	}

	return findings, risk
}

// checkBrowserCredentials checks for browser saved credentials
func (m *DataExposureCheckModule) checkBrowserCredentials() ([]string, float64) {
	var findings []string
	var risk float64

	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		return findings, risk
	}

	// Browser credential database locations
	browserPaths := map[string]string{
		"Chrome":   filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data"),
		"Edge":     filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Login Data"),
		"Firefox":  filepath.Join(userProfile, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
	}

	for browser, path := range browserPaths {
		if browser == "Firefox" {
			// Firefox has multiple profile directories
			if _, err := os.Stat(path); err == nil {
				filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
					if strings.HasSuffix(path, "logins.json") {
						findings = append(findings, fmt.Sprintf("%s password database found", browser))
						risk += 15.0
						return filepath.SkipDir
					}
					return nil
				})
			}
		} else {
			if _, err := os.Stat(path); err == nil {
				findings = append(findings, fmt.Sprintf("%s password database found", browser))
				risk += 15.0
			}
		}
	}

	return findings, risk
}

// checkEmailExposure checks for email configuration exposures
func (m *DataExposureCheckModule) checkEmailExposure() ([]string, float64) {
	var findings []string
	var risk float64

	// Check Outlook profiles
	outlookKey, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\\Microsoft\\Office\\16.0\\Outlook\\Profiles`, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		defer outlookKey.Close()

		profiles, err := outlookKey.ReadSubKeyNames(-1)
		if err == nil && len(profiles) > 0 {
			findings = append(findings, fmt.Sprintf("Found %d Outlook profiles", len(profiles)))
			risk += 10.0

			// Check for stored passwords
			for _, profile := range profiles {
				profileKey, err := registry.OpenKey(outlookKey, profile, registry.ENUMERATE_SUB_KEYS)
				if err == nil {
					defer profileKey.Close()
					findings = append(findings, fmt.Sprintf("Outlook profile '%s' may contain stored credentials", profile))
					risk += 5.0
				}
			}
		}
	}

	// Check for email client configurations
	userProfile := os.Getenv("USERPROFILE")
	if userProfile != "" {
		emailConfigs := []string{
			filepath.Join(userProfile, "AppData", "Roaming", "Thunderbird"),
			filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Outlook"),
		}

		for _, configPath := range emailConfigs {
			if _, err := os.Stat(configPath); err == nil {
				client := filepath.Base(configPath)
				findings = append(findings, fmt.Sprintf("%s configuration directory found", client))
				risk += 8.0
			}
		}
	}

	return findings, risk
}