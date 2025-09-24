package modules

import (
	"decian-agent/internal/logger"
	"fmt"
	"sync"
	"time"
)

// Runner manages the execution of assessment modules
type Runner struct {
	logger  *logger.Logger
	timeout int
	modules map[string]Module
}

// NewRunner creates a new module runner
func NewRunner(logger *logger.Logger, timeout int) *Runner {
	runner := &Runner{
		logger:  logger,
		timeout: timeout,
		modules: make(map[string]Module),
	}

	// Register available modules
	runner.registerModules()

	return runner
}

// RunModules executes the specified assessment modules
func (r *Runner) RunModules(moduleNames []string) ([]AssessmentResult, error) {
	var results []AssessmentResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	resultsChan := make(chan AssessmentResult, len(moduleNames))
	errorsChan := make(chan error, len(moduleNames))

	r.logger.Info("Starting assessment modules", map[string]interface{}{
		"modules": moduleNames,
		"timeout": r.timeout,
	})

	for _, moduleName := range moduleNames {
		module, exists := r.modules[moduleName]
		if !exists {
			r.logger.Warn("Module not found", map[string]interface{}{
				"module": moduleName,
			})
			continue
		}

		wg.Add(1)
		go func(mod Module, name string) {
			defer wg.Done()

			r.logger.Debug("Starting module execution", map[string]interface{}{
				"module": name,
			})

			startTime := time.Now()

			// Validate module can run
			if err := mod.Validate(); err != nil {
				r.logger.Error("Module validation failed", map[string]interface{}{
					"module": name,
					"error":  err.Error(),
				})
				errorsChan <- fmt.Errorf("module %s validation failed: %w", name, err)
				return
			}

			// Execute module with timeout
			done := make(chan bool, 1)
			var result *AssessmentResult
			var err error

			go func() {
				result, err = mod.Execute()
				done <- true
			}()

			select {
			case <-done:
				if err != nil {
					r.logger.Error("Module execution failed", map[string]interface{}{
						"module": name,
						"error":  err.Error(),
					})
					errorsChan <- fmt.Errorf("module %s execution failed: %w", name, err)
					return
				}

				// Set execution metadata
				result.Timestamp = startTime
				result.Duration = time.Since(startTime)

				r.logger.Info("Module completed successfully", map[string]interface{}{
					"module":     name,
					"duration":   result.Duration,
					"risk_level": result.RiskLevel,
					"risk_score": result.RiskScore,
				})

				mu.Lock()
				resultsChan <- *result
				mu.Unlock()

			case <-time.After(time.Duration(r.timeout) * time.Second):
				r.logger.Error("Module execution timed out", map[string]interface{}{
					"module":  name,
					"timeout": r.timeout,
				})
				errorsChan <- fmt.Errorf("module %s timed out after %d seconds", name, r.timeout)
			}
		}(module, moduleName)
	}

	// Wait for all modules to complete
	wg.Wait()
	close(resultsChan)
	close(errorsChan)

	// Collect results
	for result := range resultsChan {
		results = append(results, result)
	}

	// Check for errors
	var errs []error
	for err := range errorsChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		r.logger.Warn("Some modules failed", map[string]interface{}{
			"failed_count":     len(errs),
			"successful_count": len(results),
		})
		// Don't fail the entire assessment if some modules fail
		// Just log the errors and continue with successful results
		for _, err := range errs {
			r.logger.Error("Module error", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	r.logger.Info("Assessment modules completed", map[string]interface{}{
		"total_modules":      len(moduleNames),
		"successful_modules": len(results),
		"failed_modules":     len(errs),
	})

	return results, nil
}

// GetAvailableModules returns information about all available modules
func GetAvailableModules() []ModuleInfo {
	var modules []ModuleInfo

	// New security assessment modules
	modules = append(modules, ModuleInfo{
		Name:             "Misconfiguration Discovery",
		Description:      "Scan for risky configurations such as open RDP, permissive firewall rules, guest accounts, insecure protocols",
		CheckType:        CheckTypeMisconfigurationDiscovery,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelHigh,
		RequiresAdmin:    true,
	})

	modules = append(modules, ModuleInfo{
		Name:             "Weak Password Detection",
		Description:      "Identify accounts using vendor defaults or passwords found in breach dictionaries",
		CheckType:        CheckTypeWeakPasswordDetection,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelHigh,
		RequiresAdmin:    true,
	})

	modules = append(modules, ModuleInfo{
		Name:             "Data Exposure Check",
		Description:      "Scan for exposed sensitive files, cloud storage misconfigurations, and unencrypted data stores",
		CheckType:        CheckTypeDataExposureCheck,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelHigh,
		RequiresAdmin:    true,
	})

	modules = append(modules, ModuleInfo{
		Name:             "Phishing Exposure Indicators",
		Description:      "Detect browser configurations, email settings, and security features that increase phishing susceptibility",
		CheckType:        CheckTypePhishingExposureIndicators,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelHigh,
		RequiresAdmin:    false,
	})

	modules = append(modules, ModuleInfo{
		Name:             "Patch & Update Status",
		Description:      "Evaluate Windows Update configuration, missing patches, and third-party software update status",
		CheckType:        CheckTypePatchUpdateStatus,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelHigh,
		RequiresAdmin:    true,
	})

	modules = append(modules, ModuleInfo{
		Name:             "Elevated Permissions Report",
		Description:      "Identify accounts with administrative privileges, service accounts with high privileges, and privilege escalation risks",
		CheckType:        CheckTypeElevatedPermissionsReport,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelHigh,
		RequiresAdmin:    true,
	})

	modules = append(modules, ModuleInfo{
		Name:             "Excessive Sharing & Collaboration Risks",
		Description:      "Analyze network shares, file permissions, cloud storage sync, and collaboration tool configurations for data exposure risks",
		CheckType:        CheckTypeExcessiveSharingRisks,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelMedium,
		RequiresAdmin:    true,
	})

	modules = append(modules, ModuleInfo{
		Name:             "Password Policy Weakness",
		Description:      "Analyze domain and local password policies for compliance with security best practices",
		CheckType:        CheckTypePasswordPolicyWeakness,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelHigh,
		RequiresAdmin:    true,
	})

	modules = append(modules, ModuleInfo{
		Name:             "Open Service/Port Identification",
		Description:      "Identify listening services, open ports, and network service configurations that may present security risks",
		CheckType:        CheckTypeOpenServicePortID,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelMedium,
		RequiresAdmin:    false,
	})

	modules = append(modules, ModuleInfo{
		Name:             "User Behavior Risk Signals",
		Description:      "Analyze user activity patterns, installed applications, browser usage, and system configurations for security risk indicators",
		CheckType:        CheckTypeUserBehaviorRiskSignals,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelMedium,
		RequiresAdmin:    false,
	})

	return modules
}

// registerModules registers all available assessment modules
func (r *Runner) registerModules() {
	// Register new security assessment modules
	r.modules[CheckTypeMisconfigurationDiscovery] = NewMisconfigurationDiscoveryModule(r.logger)
	r.modules[CheckTypeWeakPasswordDetection] = NewWeakPasswordDetectionModule(r.logger)
	r.modules[CheckTypeDataExposureCheck] = NewDataExposureCheckModule(r.logger)
	r.modules[CheckTypePhishingExposureIndicators] = NewPhishingExposureIndicatorsModule(r.logger)
	r.modules[CheckTypePatchUpdateStatus] = NewPatchUpdateStatusModule(r.logger)
	r.modules[CheckTypeElevatedPermissionsReport] = NewElevatedPermissionsReportModule(r.logger)
	r.modules[CheckTypeExcessiveSharingRisks] = NewExcessiveSharingRisksModule(r.logger)
	r.modules[CheckTypePasswordPolicyWeakness] = NewPasswordPolicyWeaknessModule(r.logger)
	r.modules[CheckTypeOpenServicePortID] = NewOpenServicePortIDModule(r.logger)
	r.modules[CheckTypeUserBehaviorRiskSignals] = NewUserBehaviorRiskSignalsModule(r.logger)

	r.logger.Debug("Registered assessment modules", map[string]interface{}{
		"count": len(r.modules),
	})
}
