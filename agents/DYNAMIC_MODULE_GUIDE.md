# Dynamic Module Development Guide

## Overview

The Decian Agent uses a **fully dynamic module discovery system** that automatically detects and registers new security assessment modules without requiring code changes or recompilation. This guide explains how to create new modules and how the system works.

## ✅ **Benefits of Dynamic System**

- **Zero Code Changes**: Add new modules by creating a single `.go` file
- **No Recompilation**: Modules auto-register via `init()` functions
- **Automatic Discovery**: Dashboard dynamically loads modules from agents
- **Type Safety**: Full Go type checking and validation
- **Consistent Interface**: All modules implement the same `ModulePlugin` interface

---

## 🏗️ **Architecture Overview**

### Core Components

1. **Global Plugin Registry**: Modules register themselves during package initialization
2. **Plugin Manager**: Discovers and manages all registered modules
3. **Module Plugin Interface**: Standardized interface all modules must implement
4. **Auto-Discovery**: Modules are found automatically via `init()` functions

### Flow Diagram

```
[Module .go files]
    ↓ (init() functions)
[Global Registry]
    ↓ (DiscoverPlugins())
[Plugin Manager]
    ↓ (modules command)
[Dashboard API]
    ↓ (dynamic loading)
[Frontend UI]
```

---

## 📝 **Creating a New Module**

### Step 1: Choose Module Category and Location

**IMPORTANT**: Modules must be placed in the correct category subdirectory:

**For Host-Based Modules** (system checks, file scans, registry, etc.):
- Create file in: `agents/internal/modules/host-based/`
- Use package: `package hostbased`

**For Network-Based Modules** (port scans, network discovery, etc.):
- Create file in: `agents/internal/modules/network-based/`
- Use package: `package networkbased`

Example locations:
- `agents/internal/modules/host-based/registry_audit.go`
- `agents/internal/modules/network-based/port_scanner.go`

### Step 2: Required Module Structure

**For Host-Based Modules:**
```go
package hostbased

import (
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	// ... other imports
)
```

**For Network-Based Modules:**
```go
package networkbased

import (
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	// ... other imports
)
```

**⚠️ CRITICAL**: Always import `"decian-agent/internal/modules"` and prefix all module types with `modules.`

### Step 3: Complete Module Example (Network-Based)

```go
package networkbased

import (
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"fmt"
	"time"
)

// NetworkSecurityAuditModule implements network security auditing
type NetworkSecurityAuditModule struct {
	logger *logger.Logger
	info   modules.ModuleInfo
}

// NewNetworkSecurityAuditModule creates a new NetworkSecurityAuditModule instance
func NewNetworkSecurityAuditModule(logger *logger.Logger) *NetworkSecurityAuditModule {
	return &NetworkSecurityAuditModule{
		logger: logger,
		info: modules.ModuleInfo{
			Name:             "Network Security Audit",
			Description:      "Comprehensive network security assessment including firewall rules, open ports, and network protocols",
			CheckType:        "NETWORK_SECURITY_AUDIT",
			Platform:         "windows",
			DefaultRiskLevel: "HIGH",
			RequiresAdmin:    true,
			Category:         modules.CategoryNetworkBased, // ⭐ IMPORTANT: Use modules. prefix
		},
	}
}

// GetInfo returns information about the module
func (m *NetworkSecurityAuditModule) GetInfo() modules.ModuleInfo {
	return m.info
}

// Execute performs the network security audit
func (m *NetworkSecurityAuditModule) Execute() (*modules.AssessmentResult, error) {
	m.logger.Info("Starting network security audit", nil)
	startTime := time.Now()

	// TODO: Implement your security checks here
	// Example implementation would go here...

	// Calculate risk score using module utility
	riskScore := 25.0 // Example score
	riskLevel := modules.DetermineRiskLevel(riskScore) // ⭐ Use modules. prefix

	result := &modules.AssessmentResult{ // ⭐ Use modules. prefix
		CheckType: m.info.CheckType,
		RiskScore: riskScore,
		RiskLevel: riskLevel,
		Data: map[string]interface{}{
			"summary": "Network security audit completed",
			"findings": []string{},
		},
		Timestamp: time.Now(),
		Duration:  time.Since(startTime),
	}

	return result, nil
}

// Validate checks if the module can run on this system
func (m *NetworkSecurityAuditModule) Validate() error {
	// Add validation logic here
	// Example: Check if required tools/permissions are available
	return nil
}

// =============================================================================
// PLUGIN INTERFACE IMPLEMENTATION (Required)
// =============================================================================

// Plugin constructor function (Required)
func NewNetworkSecurityAuditModulePlugin(logger *logger.Logger) modules.ModulePlugin { // ⭐ Use modules. prefix
	return NewNetworkSecurityAuditModule(logger)
}

// Auto-registration via init() function (Required)
func init() {
	modules.RegisterPluginConstructor("NETWORK_SECURITY_AUDIT", NewNetworkSecurityAuditModulePlugin) // ⭐ Use modules. prefix
}
```

### Step 4: Add CheckType Constant (Required)

Add your new CheckType constant to `agents/internal/modules/types.go`:

```go
// In types.go - add to the constants section
const (
    // ... existing constants ...

    // Network-based modules
    CheckTypeNetworkSecurityAudit = "NETWORK_SECURITY_AUDIT"
)
```

### Step 5: Register Module Import (CRITICAL)

**⚠️ THIS STEP IS ESSENTIAL** - Modules won't be discovered without this!

Add the import to BOTH files:

**File 1**: `agents/cmd/modules.go`
```go
import (
    // ... existing imports ...

    // Import modules for auto-registration
    _ "decian-agent/internal/modules/host-based"
    _ "decian-agent/internal/modules/network-based" // ⭐ REQUIRED for network modules
)
```

**File 2**: `agents/cmd/run.go`
```go
import (
    // ... existing imports ...

    // Import modules for auto-registration
    _ "decian-agent/internal/modules/host-based"
    _ "decian-agent/internal/modules/network-based" // ⭐ REQUIRED for network modules
)
```
```

---

## 🔧 **Required Components Summary**

### 1. Module Struct
- Include `logger *logger.Logger` field
- Include `info modules.ModuleInfo` field
- Add any module-specific fields

### 2. Constructor Function
```go
func NewYourModule(logger *logger.Logger) *YourModule {
	return &YourModule{
		logger: logger,
		info: modules.ModuleInfo{
			Name:             "Your Module Name",
			Description:      "What your module does",
			CheckType:        "YOUR_MODULE_CHECK_TYPE",
			Platform:         "windows",
			DefaultRiskLevel: "HIGH|MEDIUM|LOW",
			RequiresAdmin:    true|false,
			Category:         modules.CategoryNetworkBased, // or modules.CategoryHostBased
		},
	}
}
```

### 3. Required Interface Methods
```go
func (m *YourModule) GetInfo() modules.ModuleInfo {
	return m.info
}

func (m *YourModule) Execute() (*modules.AssessmentResult, error) {
	// Your implementation here
}

func (m *YourModule) Validate() error {
	// Your validation here
	return nil
}
```

### 4. Plugin Constructor (Required)
```go
func NewYourModulePlugin(logger *logger.Logger) modules.ModulePlugin {
	return NewYourModule(logger)
}
```

### 5. Auto-Registration (Required)
```go
func init() {
	modules.RegisterPluginConstructor("YOUR_MODULE_CHECK_TYPE", NewYourModulePlugin)
}
```

### 5. Interface Implementation

Your module must implement `ModulePlugin`:

```go
type ModulePlugin interface {
	GetInfo() ModuleInfo
	Execute() (*AssessmentResult, error)
	Validate() error
}
```

---

## 📋 **Module Template**

### Network-Based Module Template

**File**: `agents/internal/modules/network-based/your_module.go`

```go
package networkbased

import (
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"time"
)

// YourModuleNameModule implements [description]
type YourModuleNameModule struct {
	logger *logger.Logger
	info   modules.ModuleInfo
}

// NewYourModuleNameModule creates a new instance
func NewYourModuleNameModule(logger *logger.Logger) *YourModuleNameModule {
	return &YourModuleNameModule{
		logger: logger,
		info: modules.ModuleInfo{
			Name:             "Your Module Display Name",
			Description:      "What this module checks for",
			CheckType:        "YOUR_MODULE_CHECK_TYPE",
			Platform:         "windows",
			DefaultRiskLevel: "HIGH",
			RequiresAdmin:    true,
			Category:         modules.CategoryNetworkBased,
		},
	}
}

// GetInfo returns information about the module
func (m *YourModuleNameModule) GetInfo() modules.ModuleInfo {
	return m.info
}

// Execute performs the security assessment
func (m *YourModuleNameModule) Execute() (*modules.AssessmentResult, error) {
	m.logger.Info("Starting your module assessment", nil)
	startTime := time.Now()

	// TODO: Implement your security checks here

	// Calculate risk score
	riskScore := 50.0 // Your calculation
	riskLevel := modules.DetermineRiskLevel(riskScore)

	result := &modules.AssessmentResult{
		CheckType: m.info.CheckType,
		RiskScore: riskScore,
		RiskLevel: riskLevel,
		Data: map[string]interface{}{
			"summary": "Your summary here",
			"findings": []string{},
		},
		Timestamp: time.Now(),
		Duration:  time.Since(startTime),
	}

	return result, nil
}

// Validate checks if the module can run
func (m *YourModuleNameModule) Validate() error {
	return nil
}

// Plugin constructor (Required)
func NewYourModuleNameModulePlugin(logger *logger.Logger) modules.ModulePlugin {
	return NewYourModuleNameModule(logger)
}

// Auto-registration (Required)
func init() {
	modules.RegisterPluginConstructor("YOUR_MODULE_CHECK_TYPE", NewYourModuleNameModulePlugin)
}
```

### Host-Based Module Template

**File**: `agents/internal/modules/host-based/your_module.go`

```go
package hostbased

import (
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"time"
)

// YourModuleNameModule implements [description]
type YourModuleNameModule struct {
	logger *logger.Logger
	info   modules.ModuleInfo
}

// NewYourModuleNameModule creates a new instance
func NewYourModuleNameModule(logger *logger.Logger) *YourModuleNameModule {
	return &YourModuleNameModule{
		logger: logger,
		info: modules.ModuleInfo{
			Name:             "Your Module Display Name",
			Description:      "What this module checks for",
			CheckType:        "YOUR_MODULE_CHECK_TYPE",
			Platform:         "windows",
			DefaultRiskLevel: "HIGH",
			RequiresAdmin:    true,
			Category:         modules.CategoryHostBased,
		},
	}
}

// GetInfo returns information about the module
func (m *YourModuleNameModule) GetInfo() modules.ModuleInfo {
	return m.info
}

// Execute performs the security assessment
func (m *YourModuleNameModule) Execute() (*modules.AssessmentResult, error) {
	m.logger.Info("Starting your module assessment", nil)
	startTime := time.Now()

	// TODO: Implement your security checks here

	// Calculate risk score
	riskScore := 50.0 // Your calculation
	riskLevel := modules.DetermineRiskLevel(riskScore)

	result := &modules.AssessmentResult{
		CheckType: m.info.CheckType,
		RiskScore: riskScore,
		RiskLevel: riskLevel,
		Data: map[string]interface{}{
			"summary": "Your summary here",
			"findings": []string{},
		},
		Timestamp: time.Now(),
		Duration:  time.Since(startTime),
	}

	return result, nil
}

// Validate checks if the module can run
func (m *YourModuleNameModule) Validate() error {
	return nil
}

// Plugin constructor (Required)
func NewYourModuleNameModulePlugin(logger *logger.Logger) modules.ModulePlugin {
	return NewYourModuleNameModule(logger)
}

// Auto-registration (Required)
func init() {
	modules.RegisterPluginConstructor("YOUR_MODULE_CHECK_TYPE", NewYourModuleNameModulePlugin)
}
```

---

## 🚀 **Testing Your Module**

### 1. Build and Test
```bash
cd agents
go build -o dist/test-agent.exe .
./dist/test-agent.exe modules --json
```

### 2. Verify Module Discovery
Your new module should appear in the JSON output with:
- Correct `checkType`
- Proper module information
- All required fields

### 3. Test in Dashboard
1. Download and register the updated agent
2. Create new assessment
3. Verify your module appears as a checkbox
4. Run assessment with your module selected

---

## 📚 **Key Types and Interfaces**

### ModuleInfo
```go
type ModuleInfo struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	CheckType        string `json:"checkType"`
	Platform         string `json:"platform"`
	DefaultRiskLevel string `json:"defaultRiskLevel"`
	RequiresAdmin    bool   `json:"requiresAdmin"`
}
```

### AssessmentResult
```go
type AssessmentResult struct {
	CheckType   string                 `json:"checkType"`
	RiskScore   int                    `json:"riskScore"`
	RiskLevel   string                 `json:"riskLevel"`
	Status      string                 `json:"status"`
	Findings    []Finding              `json:"findings"`
	Summary     string                 `json:"summary"`
	Remediation []string               `json:"remediation"`
	Metadata    map[string]interface{} `json:"metadata"`
}
```

### Finding
```go
type Finding struct {
	Category    string `json:"category"`
	Issue       string `json:"issue"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	Evidence    string `json:"evidence,omitempty"`
}
```

---

## 🔍 **Best Practices**

### Security Checks
- Always validate inputs and permissions
- Use secure Windows APIs
- Handle errors gracefully
- Log important operations

### Risk Scoring
- Use consistent 0-100 scale
- Document scoring methodology
- Consider severity and impact
- Provide clear risk levels

### Error Handling
```go
func (m *YourModule) Execute() (*AssessmentResult, error) {
	if err := m.checkPrerequisites(); err != nil {
		return nil, fmt.Errorf("prerequisites not met: %w", err)
	}

	// Your logic here

	if criticalError {
		m.logger.Error("Critical error during assessment", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, err
	}
}
```

### Logging
```go
// Use structured logging
m.logger.Info("Starting check", map[string]interface{}{
	"checkType": m.info.CheckType,
	"target":    "system",
})

m.logger.Debug("Detailed info", map[string]interface{}{
	"step":     "validation",
	"result":   "passed",
})

m.logger.Warn("Potential issue", map[string]interface{}{
	"issue":    "permission_denied",
	"fallback": "limited_scan",
})
```

---

## ⚙️ **System Integration**

### How Modules Are Discovered

1. **Package Initialization**: `init()` functions run when package loads
2. **Global Registry**: Modules register their constructors
3. **Plugin Manager**: Calls `DiscoverPlugins()` to find all registered modules
4. **API Endpoint**: `/api/agents/:id/modules` executes `modules --json` command
5. **Dashboard**: Fetches modules dynamically when creating assessments

### Registration Flow
```go
// 1. Module registers itself
func init() {
	RegisterPluginConstructor("YOUR_CHECK_TYPE", NewYourModulePlugin)
}

// 2. Global registry stores constructor
var globalPluginRegistry = make(map[string]PluginConstructor)

// 3. Plugin manager discovers modules
func (pm *PluginManager) DiscoverPlugins() error {
	for checkType, constructor := range globalPluginRegistry {
		pm.RegisterPlugin(checkType, constructor)
	}
}

// 4. Dashboard requests modules
GET /api/agents/:id/modules
```

---

## 🐛 **Troubleshooting**

### Module Not Appearing in Dashboard

**Most Common Issue**: Missing package imports in cmd files.

1. ✅ **Check import statements** - Verify both files have the correct imports:
   - `agents/cmd/modules.go`
   - `agents/cmd/run.go`

   Both must include:
   ```go
   _ "decian-agent/internal/modules/host-based"
   _ "decian-agent/internal/modules/network-based"
   ```

2. ✅ **Verify module location** - Module must be in correct directory:
   - Host-based: `agents/internal/modules/host-based/`
   - Network-based: `agents/internal/modules/network-based/`

3. ✅ **Check package declaration** - Must use correct package name:
   - Host-based: `package hostbased`
   - Network-based: `package networkbased`

4. ✅ **Verify modules.* prefix** - All types must be prefixed:
   - `modules.ModuleInfo` (not `ModuleInfo`)
   - `modules.AssessmentResult` (not `AssessmentResult`)
   - `modules.RegisterPluginConstructor` (not `RegisterPluginConstructor`)

5. ✅ **Check init() function** - Must use modules. prefix:
   ```go
   func init() {
       modules.RegisterPluginConstructor("YOUR_CHECK_TYPE", NewYourModulePlugin)
   }
   ```

6. ✅ **Rebuild agent** - Always rebuild after changes:
   ```bash
   go build -o dist/agent.exe .
   ```

### Module Execution Fails
1. Verify `Validate()` method returns `nil`
2. Check required permissions/tools are available
3. Review error logs in agent output
4. Test module logic independently

### Common Issues
- **Duplicate CheckType**: Each module must have unique identifier
- **Missing imports in cmd/**: Module won't be discovered without proper imports
- **Wrong package name**: Must use `hostbased` or `networkbased`
- **Missing modules. prefix**: All types must be prefixed with `modules.`
- **Wrong file location**: Must be in correct subdirectory

---

## 📖 **Examples**

See existing modules for reference:
- `misconfiguration_discovery.go` - Registry and service checks
- `weak_password_detection.go` - Authentication security
- `data_exposure_check.go` - File system scanning
- `phishing_exposure_indicators.go` - Browser/email security

---

## 🎯 **Summary**

Creating a new security assessment module requires these **5 CRITICAL steps**:

### ✅ **Step-by-Step Checklist**

1. **📁 File Location & Package**
   - Place in correct subdirectory: `host-based/` or `network-based/`
   - Use correct package: `package hostbased` or `package networkbased`
   - Always import: `"decian-agent/internal/modules"`

2. **🏗️ Module Structure**
   - Implement `modules.ModulePlugin` interface
   - Use `modules.ModuleInfo` struct with `modules.CategoryHostBased` or `modules.CategoryNetworkBased`
   - Prefix ALL types with `modules.` (ModuleInfo, AssessmentResult, etc.)

3. **🔌 Plugin Registration**
   - Create plugin constructor: `func NewYourModulePlugin(logger *logger.Logger) modules.ModulePlugin`
   - Add init function: `modules.RegisterPluginConstructor("CHECK_TYPE", NewYourModulePlugin)`

4. **📝 Constants & Imports**
   - Add CheckType constant to `agents/internal/modules/types.go`
   - **CRITICAL**: Add import to `agents/cmd/modules.go` and `agents/cmd/run.go`:
     ```go
     _ "decian-agent/internal/modules/network-based"
     ```

5. **🔨 Build & Test**
   - Rebuild agent: `go build -o dist/agent.exe .`
   - Test discovery: `./dist/agent.exe modules --json`
   - Verify module appears in dashboard

### ⚠️ **Critical Success Factors**

- **Import statements in cmd/ files** - Without these, modules won't be discovered
- **Correct package names** - `hostbased` vs `networkbased`
- **modules.* prefixes** - All types must be prefixed
- **Proper file locations** - Must be in category subdirectories

**💡 Tip**: Follow the updated templates exactly - they now include all correct patterns for successful module integration!