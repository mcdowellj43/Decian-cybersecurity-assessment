# Agents Directory Overview

## Architecture
**Go-based Windows security assessment agent** using Cobra CLI framework (Go 1.21+)
- **Entry Point**: `main.go` → executes CLI commands via `cmd/` package
- **Module**: `decian-agent` with dependencies: Cobra, Viper, YAML

## Core Components
- **Commands**: `register`, `run`, `status` (cmd/*.go)
- **Configuration**: YAML-based config system (.decian-agent.yaml) with Viper
- **Communication**: Dashboard HTTP client with JWT authentication
- **Logging**: Structured logging with configurable levels
- **Assessment Engine**: Modular plugin system for security checks

## Configuration Structure
```yaml
agent: {id, hostname, version, dry_run}
dashboard: {url, timeout}
auth: {token}
assessment: {default_modules, module_config}
logging: {verbose, level, file}
```

## Implemented Modules
 MISCONFIGURATION_DISCOVERY
  WEAK_PASSWORD_DETECTION  
  DATA_EXPOSURE_CHECK
  PHISHING_EXPOSURE_INDICATORS
  PATCH_UPDATE_STATUS
  ELEVATED_PERMISSIONS_REPORT
  EXCESSIVE_SHARING_RISKS
  PASSWORD_POLICY_WEAKNESS
  OPEN_SERVICE_PORT_ID
  USER_BEHAVIOR_RISK_SIGNALS

## Status: 70% Complete
✅ CLI framework, config system, dashboard client
🔄 Testing agent-to-dashboard communication flow
⏳ Additional assessment modules pending implementation