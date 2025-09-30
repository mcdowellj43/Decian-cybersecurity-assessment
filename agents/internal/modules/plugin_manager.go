package modules

import (
	"decian-agent/internal/logger"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
)

// PluginConstructor represents a function that creates a new plugin instance
type PluginConstructor func(*logger.Logger) ModulePlugin

// PluginRegistry holds information about a registered plugin
type PluginRegistry struct {
	Constructor PluginConstructor
	Info        ModuleInfo
	Type        reflect.Type
}

// PluginManager handles discovery, registration, and lifecycle of assessment module plugins
type PluginManager struct {
	logger   *logger.Logger
	mutex    sync.RWMutex
	plugins  map[string]*PluginRegistry
	registry map[string]ModuleInfo
}

// Global registry for auto-discovery
var globalPluginRegistry = make(map[string]PluginConstructor)
var globalRegistryMutex sync.RWMutex

// RegisterPluginConstructor registers a plugin constructor for auto-discovery
// This should be called during package initialization by each module
func RegisterPluginConstructor(checkType string, constructor PluginConstructor) {
	globalRegistryMutex.Lock()
	defer globalRegistryMutex.Unlock()
	globalPluginRegistry[checkType] = constructor
}

// NewPluginManager creates a new plugin manager instance
func NewPluginManager(logger *logger.Logger) *PluginManager {
	return &PluginManager{
		logger:   logger,
		plugins:  make(map[string]*PluginRegistry),
		registry: make(map[string]ModuleInfo),
	}
}

// RegisterPlugin manually registers a plugin with the manager
func (pm *PluginManager) RegisterPlugin(checkType string, constructor PluginConstructor) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Create an instance to get module info
	instance := constructor(pm.logger)
	info := instance.GetInfo()

	// Validate that the checkType matches
	if info.CheckType != checkType {
		return fmt.Errorf("checkType mismatch: expected %s, got %s", checkType, info.CheckType)
	}

	// Store the plugin registry
	pm.plugins[checkType] = &PluginRegistry{
		Constructor: constructor,
		Info:        info,
		Type:        reflect.TypeOf(instance),
	}

	pm.registry[checkType] = info

	pm.logger.Debug("Plugin registered", map[string]interface{}{
		"checkType": checkType,
		"name":      info.Name,
		"type":      reflect.TypeOf(instance).String(),
	})

	return nil
}

// GetPlugin creates a new instance of the specified plugin
func (pm *PluginManager) GetPlugin(checkType string) (ModulePlugin, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	registry, exists := pm.plugins[checkType]
	if !exists {
		return nil, fmt.Errorf("plugin not found: %s", checkType)
	}

	// Create new instance
	instance := registry.Constructor(pm.logger)
	return instance, nil
}

// GetPluginInfo returns information about a specific plugin
func (pm *PluginManager) GetPluginInfo(checkType string) (ModuleInfo, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	info, exists := pm.registry[checkType]
	if !exists {
		return ModuleInfo{}, fmt.Errorf("plugin not found: %s", checkType)
	}

	return info, nil
}

// GetAllPluginInfo returns information about all registered plugins
func (pm *PluginManager) GetAllPluginInfo() []ModuleInfo {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var modules []ModuleInfo
	for _, info := range pm.registry {
		modules = append(modules, info)
	}

	return modules
}

// GetRegisteredPlugins returns a list of all registered plugin check types
func (pm *PluginManager) GetRegisteredPlugins() []string {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var checkTypes []string
	for checkType := range pm.plugins {
		checkTypes = append(checkTypes, checkType)
	}

	return checkTypes
}

// IsPluginRegistered checks if a plugin is registered
func (pm *PluginManager) IsPluginRegistered(checkType string) bool {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	_, exists := pm.plugins[checkType]
	return exists
}

// GetPluginCount returns the number of registered plugins
func (pm *PluginManager) GetPluginCount() int {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	return len(pm.plugins)
}

// ValidatePlugin checks if a plugin instance implements required interfaces correctly
func (pm *PluginManager) ValidatePlugin(plugin ModulePlugin) error {
	// Basic interface validation
	if plugin == nil {
		return fmt.Errorf("plugin instance is nil")
	}

	// Check if GetInfo returns valid data
	info := plugin.GetInfo()
	if info.CheckType == "" {
		return fmt.Errorf("plugin GetInfo() returned empty CheckType")
	}
	if info.Name == "" {
		return fmt.Errorf("plugin GetInfo() returned empty Name")
	}

	// Check if Validate method works
	if err := plugin.Validate(); err != nil {
		pm.logger.Debug("Plugin validation returned error (this may be expected)", map[string]interface{}{
			"checkType": info.CheckType,
			"error":     err.Error(),
		})
	}

	return nil
}

// CreatePluginInstance creates a new plugin instance and validates it
func (pm *PluginManager) CreatePluginInstance(checkType string) (ModulePlugin, error) {
	plugin, err := pm.GetPlugin(checkType)
	if err != nil {
		return nil, err
	}

	if err := pm.ValidatePlugin(plugin); err != nil {
		return nil, fmt.Errorf("plugin validation failed: %w", err)
	}

	return plugin, nil
}

// DiscoverPlugins automatically discovers and registers all plugins using the global registry
// Modules register themselves during package initialization
func (pm *PluginManager) DiscoverPlugins() error {
	pm.logger.Info("Starting plugin auto-discovery from global registry", nil)

	globalRegistryMutex.RLock()
	constructors := make(map[string]PluginConstructor)
	for checkType, constructor := range globalPluginRegistry {
		constructors[checkType] = constructor
	}
	globalRegistryMutex.RUnlock()

	registeredCount := 0
	for checkType, constructor := range constructors {
		// Try to register the plugin
		if err := pm.RegisterPlugin(checkType, constructor); err != nil {
			pm.logger.Warn("Failed to register discovered plugin", map[string]interface{}{
				"checkType": checkType,
				"error":     err.Error(),
			})
			continue
		}

		registeredCount++
		pm.logger.Info("Auto-discovered and registered plugin", map[string]interface{}{
			"checkType": checkType,
		})
	}

	pm.logger.Info("Plugin auto-discovery completed", map[string]interface{}{
		"discovered": len(constructors),
		"registered": registeredCount,
	})

	return nil
}

// findPluginConstructors uses reflection to find all functions that match the plugin constructor pattern
func (pm *PluginManager) findPluginConstructors() map[string]PluginConstructor {
	constructors := make(map[string]PluginConstructor)

	// Get the current package path
	pc, _, _, ok := runtime.Caller(0)
	if !ok {
		pm.logger.Error("Failed to get caller information for plugin discovery", nil)
		return constructors
	}

	funcName := runtime.FuncForPC(pc).Name()
	packagePath := funcName[:strings.LastIndex(funcName, ".")]

	pm.logger.Debug("Searching for plugin constructors", map[string]interface{}{
		"package": packagePath,
	})

	// We'll use a different approach - checking for specific known constructor functions
	// This is more reliable than trying to enumerate all functions via reflection
	knownConstructors := map[string]string{
		"NewMisconfigurationDiscoveryModule":  "MISCONFIGURATION_DISCOVERY",
		"NewWeakPasswordDetectionModule":      "WEAK_PASSWORD_DETECTION",
		"NewDataExposureCheckModule":          "DATA_EXPOSURE_CHECK",
		"NewPhishingExposureIndicatorsModule": "PHISHING_EXPOSURE_INDICATORS",
		"NewPatchUpdateStatusModule":          "PATCH_UPDATE_STATUS",
		"NewElevatedPermissionsReportModule":  "ELEVATED_PERMISSIONS_REPORT",
		"NewExcessiveSharingRisksModule":      "EXCESSIVE_SHARING_RISKS",
		"NewPasswordPolicyWeaknessModule":     "PASSWORD_POLICY_WEAKNESS",
		"NewOpenServicePortIDModule":          "OPEN_SERVICE_PORT_ID",
		"NewUserBehaviorRiskSignalsModule":    "USER_BEHAVIOR_RISK_SIGNALS",
	}

	// Try to find each known constructor function
	for funcName, checkType := range knownConstructors {
		if constructor := pm.tryGetConstructorFunction(funcName); constructor != nil {
			constructors[funcName] = constructor
			pm.logger.Debug("Found plugin constructor", map[string]interface{}{
				"function":  funcName,
				"checkType": checkType,
			})
		}
	}

	return constructors
}

// tryGetConstructorFunction attempts to get a constructor function by name using reflection
func (pm *PluginManager) tryGetConstructorFunction(funcName string) PluginConstructor {
	defer func() {
		if r := recover(); r != nil {
			pm.logger.Debug("Failed to get constructor function", map[string]interface{}{
				"function": funcName,
				"error":    fmt.Sprintf("%v", r),
			})
		}
	}()

	// Since we can't easily enumerate package functions via reflection,
	// we'll use a registry approach where each module registers itself
	// For now, return nil - this will be handled by manual registration
	return nil
}

// extractCheckTypeFromFunctionName converts a function name to a check type
// Example: NewMisconfigurationDiscoveryModule -> MISCONFIGURATION_DISCOVERY
func (pm *PluginManager) extractCheckTypeFromFunctionName(funcName string) string {
	// Remove "New" prefix and "Module" suffix
	if !strings.HasPrefix(funcName, "New") || !strings.HasSuffix(funcName, "Module") {
		return ""
	}

	// Extract middle part
	middle := funcName[3 : len(funcName)-6] // Remove "New" and "Module"

	// Convert CamelCase to UPPER_SNAKE_CASE
	var result strings.Builder
	for i, r := range middle {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteString("_")
		}
		result.WriteRune(r)
	}

	return strings.ToUpper(result.String())
}

