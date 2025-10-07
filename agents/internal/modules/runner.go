package modules

import (
	"decian-agent/internal/logger"
	"fmt"
	"time"
)

// Runner manages the execution of assessment modules

type Runner struct {
	logger        *logger.Logger
	timeout       int
	pluginManager *PluginManager // Plugin manager for dynamic modules
}

// NewRunner creates a new module runner
func NewRunner(logger *logger.Logger, timeout int) *Runner {
	runner := &Runner{
		logger:        logger,
		timeout:       timeout,
		pluginManager: NewPluginManager(logger),
	}

	// Use dynamic auto-discovery system
	runner.pluginManager.DiscoverPlugins()

	return runner
}

// ModuleExecutionError captures a single module failure.
type ModuleExecutionError struct {
	Module string
	Err    error
}

func (e ModuleExecutionError) Error() string {
	if e.Err == nil {
		return e.Module + " failed"
	}
	return fmt.Sprintf("%s: %s", e.Module, e.Err.Error())
}

// RunModules executes modules without a specific target context.
func (r *Runner) RunModules(moduleNames []string) ([]AssessmentResult, []ModuleExecutionError) {
	return r.RunModulesForTarget(moduleNames, TargetContext{})
}

// RunModulesForTarget executes the specified assessment modules sequentially for a single target.
func (r *Runner) RunModulesForTarget(moduleNames []string, target TargetContext) ([]AssessmentResult, []ModuleExecutionError) {
	r.logger.Info("Starting assessment modules", map[string]interface{}{
		"modules": moduleNames,
		"timeout": r.timeout,
		"target":  target.IP,
	})

	var results []AssessmentResult
	var errors []ModuleExecutionError

	for _, moduleName := range moduleNames {
		// Try to get module from plugin manager first (new system)
		var module Module
		var modulePlugin ModulePlugin

		if r.pluginManager.IsPluginRegistered(moduleName) {
			// Use new plugin system
			plugin, err := r.pluginManager.CreatePluginInstance(moduleName)
			if err != nil {
				r.logger.Warn("Plugin creation failed", map[string]interface{}{
					"module": moduleName,
					"error":  err.Error(),
				})
				errors = append(errors, ModuleExecutionError{Module: moduleName, Err: err})
				continue
			}
			modulePlugin = plugin

			// Check if it's also a legacy Module (for backward compatibility)
			if legacyModule, ok := plugin.(Module); ok {
				module = legacyModule
			} else {
				// Create a wrapper to make plugin compatible with legacy Module interface
				module = &pluginToModuleAdapter{plugin: plugin}
			}
		} else {
			// Module not found in plugin system
			r.logger.Warn("Module not found in plugin registry", map[string]interface{}{"module": moduleName})
			errors = append(errors, ModuleExecutionError{Module: moduleName, Err: fmt.Errorf("module not registered")})
			continue
		}

		// Set target context if the module supports it
		if targeted, ok := module.(TargetAwareModule); ok {
			targeted.SetTarget(target)
		} else if targetedPlugin, ok := modulePlugin.(TargetAwarePlugin); ok {
			targetedPlugin.SetTarget(target)
		}

		r.logger.Debug("Starting module execution", map[string]interface{}{
			"module": moduleName,
			"target": target.IP,
		})

		startTime := time.Now()

		if err := module.Validate(); err != nil {
			r.logger.Error("Module validation failed", map[string]interface{}{
				"module": moduleName,
				"target": target.IP,
				"error":  err.Error(),
			})
			errors = append(errors, ModuleExecutionError{Module: moduleName, Err: fmt.Errorf("validation failed: %w", err)})
			continue
		}

		resultCh := make(chan *AssessmentResult, 1)
		errCh := make(chan error, 1)

		go func(mod Module) {
			res, err := mod.Execute()
			if err != nil {
				errCh <- err
				return
			}
			resultCh <- res
		}(module)

		select {
		case res := <-resultCh:
			res.Timestamp = startTime
			res.Duration = time.Since(startTime)
			if res.Data == nil {
				res.Data = map[string]interface{}{}
			}
			if target.IP != "" {
				res.Data["targetIp"] = target.IP
			}
			if len(target.Metadata) > 0 {
				res.Data["targetMetadata"] = target.Metadata
			}

			r.logger.Info("Module completed successfully", map[string]interface{}{
				"module":     moduleName,
				"target":     target.IP,
				"duration":   res.Duration,
				"risk_level": res.RiskLevel,
				"risk_score": res.RiskScore,
			})

			results = append(results, *res)

		case err := <-errCh:
			r.logger.Error("Module execution failed", map[string]interface{}{
				"module": moduleName,
				"target": target.IP,
				"error":  err.Error(),
			})
			errors = append(errors, ModuleExecutionError{Module: moduleName, Err: fmt.Errorf("execution failed: %w", err)})

		case <-time.After(time.Duration(r.timeout) * time.Second):
			r.logger.Error("Module execution timed out", map[string]interface{}{
				"module":  moduleName,
				"target":  target.IP,
				"timeout": r.timeout,
			})
			errors = append(errors, ModuleExecutionError{Module: moduleName, Err: fmt.Errorf("timed out after %d seconds", r.timeout)})
		}
	}

	r.logger.Info("Assessment modules completed", map[string]interface{}{
		"total_modules":      len(moduleNames),
		"successful_modules": len(results),
		"failed_modules":     len(errors),
		"target":             target.IP,
	})

	return results, errors
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


// pluginToModuleAdapter adapts a ModulePlugin to the legacy Module interface
// This ensures backward compatibility when using new plugins with legacy code
type pluginToModuleAdapter struct {
	plugin ModulePlugin
}

// GetInfo implements ModulePlugin interface by delegating to the wrapped plugin
func (a *pluginToModuleAdapter) GetInfo() ModuleInfo {
	return a.plugin.GetInfo()
}

// Execute implements ModulePlugin interface by delegating to the wrapped plugin
func (a *pluginToModuleAdapter) Execute() (*AssessmentResult, error) {
	return a.plugin.Execute()
}

// Validate implements ModulePlugin interface by delegating to the wrapped plugin
func (a *pluginToModuleAdapter) Validate() error {
	return a.plugin.Validate()
}

// Info implements the legacy Module interface by delegating to GetInfo
func (a *pluginToModuleAdapter) Info() ModuleInfo {
	return a.plugin.GetInfo()
}

// GetAvailableModulesFromPluginManager returns module info from the plugin manager
func (r *Runner) GetAvailableModulesFromPluginManager() []ModuleInfo {
	return r.pluginManager.GetAllPluginInfo()
}

// GetPluginManager returns the plugin manager instance for external access
func (r *Runner) GetPluginManager() *PluginManager {
	return r.pluginManager
}
