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
			"failed_count":    len(errs),
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
		"total_modules":    len(moduleNames),
		"successful_modules": len(results),
		"failed_modules":   len(errs),
	})

	return results, nil
}

// GetAvailableModules returns information about all available modules
func GetAvailableModules() []ModuleInfo {
	var modules []ModuleInfo

	// Return module info for all available modules
	// This would be populated as modules are implemented
	modules = append(modules, ModuleInfo{
		Name:             "Windows Update Check",
		Description:      "Checks for missing Windows updates and patch status",
		CheckType:        CheckTypeWinUpdateCheck,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelMedium,
		RequiresAdmin:    true,
	})

	modules = append(modules, ModuleInfo{
		Name:             "Windows Firewall Status",
		Description:      "Checks Windows Firewall configuration and status",
		CheckType:        CheckTypeWinFirewallStatusCheck,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelHigh,
		RequiresAdmin:    false,
	})

	modules = append(modules, ModuleInfo{
		Name:             "PowerShell Execution Policy",
		Description:      "Checks PowerShell execution policy settings",
		CheckType:        CheckTypePshellExecPolicyCheck,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelMedium,
		RequiresAdmin:    false,
	})

	modules = append(modules, ModuleInfo{
		Name:             "End-of-Life Software Detection",
		Description:      "Detects installed software that is end-of-life",
		CheckType:        CheckTypeEOLSoftwareCheck,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelHigh,
		RequiresAdmin:    false,
	})

	return modules
}

// registerModules registers all available assessment modules
func (r *Runner) registerModules() {
	// Register Windows Update Check module
	r.modules[CheckTypeWinUpdateCheck] = NewWinUpdateCheckModule(r.logger)

	// Additional modules would be registered here as they're implemented
	// r.modules[CheckTypeWinFirewallStatusCheck] = NewWinFirewallModule(r.logger)
	// r.modules[CheckTypePshellExecPolicyCheck] = NewPowerShellPolicyModule(r.logger)
	// etc.

	r.logger.Debug("Registered assessment modules", map[string]interface{}{
		"count": len(r.modules),
	})
}