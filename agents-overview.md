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
1. **WIN_UPDATE_CHECK** - Windows Update status assessment via PowerShell
2. **WIN_FIREWALL_STATUS_CHECK** - Default module (framework ready)
3. **PSHELL_EXEC_POLICY_CHECK** - Default module (framework ready)
4. **EOL_SOFTWARE_CHECK** - Default module (framework ready)

## Status: 70% Complete
✅ CLI framework, config system, dashboard client
🔄 Testing agent-to-dashboard communication flow
⏳ Additional assessment modules pending implementation