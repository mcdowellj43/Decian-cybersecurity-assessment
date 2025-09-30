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

### Step 1: Create the Module File

Create a new file in `agents/internal/modules/` following the naming pattern: `{module_name}.go`

Example: `network_security_audit.go`

### Step 2: Required Module Structure

```go
package modules

import (
	"decian-agent/internal/logger"
)

// NetworkSecurityAuditModule implements network security auditing
type NetworkSecurityAuditModule struct {
	BaseModule
	logger *logger.Logger
}

// NewNetworkSecurityAuditModule creates a new NetworkSecurityAuditModule instance
func NewNetworkSecurityAuditModule(logger *logger.Logger) *NetworkSecurityAuditModule {
	return &NetworkSecurityAuditModule{
		BaseModule: BaseModule{
			info: ModuleInfo{
				Name:             "Network Security Audit",
				Description:      "Comprehensive network security assessment including firewall rules, open ports, and network protocols",
				CheckType:        "NETWORK_SECURITY_AUDIT",
				Platform:         "windows",
				DefaultRiskLevel: "HIGH",
				RequiresAdmin:    true,
			},
		},
		logger: logger,
	}
}

// Execute performs the network security audit
func (m *NetworkSecurityAuditModule) Execute() (*AssessmentResult, error) {
	m.logger.Info("Starting network security audit", nil)

	// TODO: Implement your security checks here
	// Example implementation:
	findings := []Finding{}

	// Check firewall status
	if !m.checkFirewallEnabled() {
		findings = append(findings, Finding{
			Category:    "Firewall",
			Issue:       "Windows Firewall is disabled",
			Severity:    "HIGH",
			Description: "System firewall is not protecting against network threats",
			Remediation: "Enable Windows Firewall for all network profiles",
		})
	}

	// Calculate risk score based on findings
	riskScore := m.calculateRiskScore(findings)

	return &AssessmentResult{
		CheckType:   m.info.CheckType,
		RiskScore:   riskScore,
		RiskLevel:   m.determineRiskLevel(riskScore),
		Status:      "COMPLETED",
		Findings:    findings,
		Summary:     m.generateSummary(findings),
		Remediation: m.generateRemediation(findings),
		Metadata: map[string]interface{}{
			"total_checks":     1,
			"findings_count":   len(findings),
			"execution_time":   "2.3s",
		},
	}, nil
}

// Validate checks if the module can run on this system
func (m *NetworkSecurityAuditModule) Validate() error {
	// Add validation logic here
	// Example: Check if required tools/permissions are available
	return nil
}

// Helper methods for your specific checks
func (m *NetworkSecurityAuditModule) checkFirewallEnabled() bool {
	// Implement firewall check logic
	return true
}

func (m *NetworkSecurityAuditModule) calculateRiskScore(findings []Finding) int {
	// Implement risk scoring logic
	if len(findings) == 0 {
		return 10 // Low risk
	}
	return 85 // High risk for demo
}

func (m *NetworkSecurityAuditModule) determineRiskLevel(score int) string {
	if score >= 80 {
		return "HIGH"
	} else if score >= 50 {
		return "MEDIUM"
	}
	return "LOW"
}

func (m *NetworkSecurityAuditModule) generateSummary(findings []Finding) string {
	if len(findings) == 0 {
		return "Network security configuration appears secure"
	}
	return fmt.Sprintf("Found %d network security issues requiring attention", len(findings))
}

func (m *NetworkSecurityAuditModule) generateRemediation(findings []Finding) []string {
	remediations := []string{}
	for _, finding := range findings {
		remediations = append(remediations, finding.Remediation)
	}
	return remediations
}

// =============================================================================
// PLUGIN INTERFACE IMPLEMENTATION (Required)
// =============================================================================

// NewNetworkSecurityAuditModulePlugin creates a new plugin instance
func NewNetworkSecurityAuditModulePlugin(logger *logger.Logger) ModulePlugin {
	return NewNetworkSecurityAuditModule(logger)
}

// Auto-registration via init() function
func init() {
	RegisterPluginConstructor("NETWORK_SECURITY_AUDIT", NewNetworkSecurityAuditModulePlugin)
}
```

### Step 3: Required Constants

If your module needs specific constants, add them to `types.go`:

```go
// Add to agents/internal/modules/types.go
const (
	// ... existing constants ...
	CheckTypeNetworkSecurityAudit = "NETWORK_SECURITY_AUDIT"
)
```

---

## 🔧 **Required Components**

### 1. Module Struct
- Must embed `BaseModule`
- Include `logger *logger.Logger` field
- Add any module-specific fields

### 2. Constructor Function
```go
func NewYourModule(logger *logger.Logger) *YourModule {
	return &YourModule{
		BaseModule: BaseModule{
			info: ModuleInfo{
				Name:             "Your Module Name",
				Description:      "What your module does",
				CheckType:        "YOUR_MODULE_CHECK_TYPE",
				Platform:         "windows",
				DefaultRiskLevel: "HIGH|MEDIUM|LOW",
				RequiresAdmin:    true|false,
			},
		},
		logger: logger,
	}
}
```

### 3. Plugin Constructor (Required)
```go
func NewYourModulePlugin(logger *logger.Logger) ModulePlugin {
	return NewYourModule(logger)
}
```

### 4. Auto-Registration (Required)
```go
func init() {
	RegisterPluginConstructor("YOUR_MODULE_CHECK_TYPE", NewYourModulePlugin)
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

Use this template for new modules:

```go
package modules

import (
	"decian-agent/internal/logger"
)

// YourModuleNameModule implements [description]
type YourModuleNameModule struct {
	BaseModule
	logger *logger.Logger
}

// NewYourModuleNameModule creates a new instance
func NewYourModuleNameModule(logger *logger.Logger) *YourModuleNameModule {
	return &YourModuleNameModule{
		BaseModule: BaseModule{
			info: ModuleInfo{
				Name:             "Your Module Display Name",
				Description:      "What this module checks for",
				CheckType:        "YOUR_MODULE_CHECK_TYPE",
				Platform:         "windows",
				DefaultRiskLevel: "HIGH",
				RequiresAdmin:    true,
			},
		},
		logger: logger,
	}
}

// Execute performs the security assessment
func (m *YourModuleNameModule) Execute() (*AssessmentResult, error) {
	m.logger.Info("Starting your module assessment", nil)

	// TODO: Implement your security checks here
	findings := []Finding{}

	// Your assessment logic goes here

	riskScore := m.calculateRiskScore(findings)

	return &AssessmentResult{
		CheckType:   m.info.CheckType,
		RiskScore:   riskScore,
		RiskLevel:   m.determineRiskLevel(riskScore),
		Status:      "COMPLETED",
		Findings:    findings,
		Summary:     "Your summary here",
		Remediation: []string{"Your remediation steps"},
		Metadata: map[string]interface{}{
			"execution_time": "1.5s",
		},
	}, nil
}

// Validate checks if the module can run
func (m *YourModuleNameModule) Validate() error {
	return nil
}

// Plugin constructor (Required)
func NewYourModuleNameModulePlugin(logger *logger.Logger) ModulePlugin {
	return NewYourModuleNameModule(logger)
}

// Auto-registration (Required)
func init() {
	RegisterPluginConstructor("YOUR_MODULE_CHECK_TYPE", NewYourModuleNameModulePlugin)
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
1. Check `init()` function is present and correct
2. Verify `CheckType` is unique
3. Ensure module compiles without errors
4. Check agent executable was rebuilt after adding module

### Module Execution Fails
1. Verify `Validate()` method returns `nil`
2. Check required permissions/tools are available
3. Review error logs in agent output
4. Test module logic independently

### Common Issues
- **Duplicate CheckType**: Each module must have unique identifier
- **Missing init()**: Module won't be discovered without auto-registration
- **Import errors**: Ensure all dependencies are available
- **Permission issues**: Some checks require admin privileges

---

## 📖 **Examples**

See existing modules for reference:
- `misconfiguration_discovery.go` - Registry and service checks
- `weak_password_detection.go` - Authentication security
- `data_exposure_check.go` - File system scanning
- `phishing_exposure_indicators.go` - Browser/email security

---

## 🎯 **Summary**

Creating a new security assessment module requires:

1. ✅ **Create `.go` file** in `agents/internal/modules/`
2. ✅ **Implement ModulePlugin interface** (`GetInfo`, `Execute`, `Validate`)
3. ✅ **Add plugin constructor** function
4. ✅ **Include init() function** for auto-registration
5. ✅ **Test and verify** module appears in dashboard

The dynamic system handles everything else automatically - no code changes, no recompilation of other components, no manual registration required!

---

**💡 Tip**: Start with the provided template and gradually add your specific security assessment logic. The system is designed to be developer-friendly while maintaining consistency and reliability.