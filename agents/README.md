# Decian Security Agent

This is the Go-based security assessment agent for the Decian Cybersecurity Assessment Platform with **embedded configuration** and **automatic setup** capabilities.

## Quick Start (End Users)

1. **Download**: Get `decian-agent-{your-org}.exe` from your administrator
2. **Setup**: Run `.\decian-agent-{your-org}.exe setup`
3. **Assess**: Run `.\decian-agent-{your-org}.exe run`
4. **View Results**: Check results in your dashboard

## Building Organization-Specific Agents (Administrators)

### Prerequisites

1. **Go 1.21+**: Download from [golang.org](https://golang.org/download/)
2. **Git**: For cloning the repository
3. **Windows**: The agent targets Windows systems

### Building an Agent

#### Using PowerShell (Windows)
```powershell
cd agents
.\scripts\build-agent.ps1 -OrgId "your-org-id" -DashboardUrl "https://your-dashboard.com"
```

#### Using Bash (Linux/macOS/WSL)
```bash
cd agents
./scripts/build-agent.sh --org-id "your-org-id" --dashboard-url "https://your-dashboard.com"
```

### Build Output

The build process will:

1. **Generate Configuration**: Create organization-specific YAML config
2. **Embed Configuration**: Embed the config into the executable at build time
3. **Build Executable**: Compile to `dist/decian-agent-{org-id}.exe`
4. **Provide Instructions**: Show distribution instructions

## Agent Commands

### Setup Command (New - Recommended)
```powershell
.\decian-agent-{org-id}.exe setup
```
- Interactive setup wizard
- Automatically connects to dashboard using embedded configuration
- No manual configuration required
- Registers agent automatically

### Legacy Commands (Still supported)
```powershell
# Register manually
.\decian-agent.exe register --dashboard https://dashboard.com --token your-token

# Run assessment
.\decian-agent.exe run

# Check status
.\decian-agent.exe status
```

## Features

- **Comprehensive Security Checks**: Multiple assessment modules covering Windows updates, firewall, PowerShell policies, and more
- **Dashboard Integration**: Secure communication with Decian dashboard for centralized management
- **Flexible Configuration**: YAML-based configuration with command-line overrides
- **Robust Logging**: Structured logging with configurable verbosity
- **Parallel Execution**: Concurrent module execution for faster assessments

## Quick Start

### Prerequisites

- Windows Server 2016+ or Windows 10+
- PowerShell 5.0+
- Administrator privileges (for some security checks)
- Go 1.21+ (for building from source)

### Installation

#### Option 1: Download Pre-built Binary
Download the latest release from the [releases page](releases) and extract to your desired location.

#### Option 2: Build from Source
```bash
# Clone the repository
git clone <repository-url>
cd agents

# Build the agent
go build -o decian-agent.exe .
```

### Configuration

1. Copy the example configuration file:
```bash
copy .decian-agent.example.yaml .decian-agent.yaml
```

2. Edit `.decian-agent.yaml` with your dashboard details:
```yaml
dashboard:
  url: "https://your-dashboard.example.com"

auth:
  token: "your-jwt-token-here"
```

### Usage

#### Register the Agent
```bash
decian-agent register --dashboard https://your-dashboard.com --token your-jwt-token
```

#### Run Security Assessment
```bash
# Run all configured modules
decian-agent run

# Run specific modules
decian-agent run --modules WIN_UPDATE_CHECK,WIN_FIREWALL_STATUS_CHECK

# Dry run (don't submit results)
decian-agent run --dry-run
```

#### Check Agent Status
```bash
decian-agent status
```

#### List Available Modules
```bash
decian-agent run --list-modules
```

## Available Assessment Modules

| Module | Description | Risk Level | Admin Required |
|--------|-------------|------------|----------------|
| `WIN_UPDATE_CHECK` | Windows Update status and missing patches | Medium | Yes |
| `WIN_FIREWALL_STATUS_CHECK` | Windows Firewall configuration | High | No |
| `PSHELL_EXEC_POLICY_CHECK` | PowerShell execution policy settings | Medium | No |
| `EOL_SOFTWARE_CHECK` | End-of-life software detection | High | No |
| `ACCOUNTS_BYPASS_PASS_POLICY` | Account password policy analysis | High | Yes |
| `DC_OPEN_PORTS_CHECK` | Domain Controller port security | Critical | Yes |
| `DNS_CONFIG_CHECK` | DNS security configuration | Medium | No |
| `ENABLED_INACTIVE_ACCOUNTS` | Inactive account detection | Medium | Yes |
| `NETWORK_PROTOCOLS_CHECK` | Network protocol security | High | No |
| `SERVICE_ACCOUNTS_DOMAIN_ADMIN` | Service account privilege analysis | Critical | Yes |
| `PRIVILEGED_ACCOUNTS_NO_EXPIRE` | Privileged account expiration | High | Yes |

## Configuration Reference

### Command Line Options

```bash
# Global flags
--config string     Config file path (default: .decian-agent.yaml)
--dashboard string  Dashboard API endpoint URL
--token string      Authentication token
--verbose           Enable verbose logging
--dry-run          Run without submitting results

# Register command
decian-agent register [flags]
  --hostname string   Override hostname for registration
  --version string    Agent version (default "1.0.0")

# Run command
decian-agent run [flags]
  --modules strings   Specific modules to run
  --list-modules      List available modules
  --timeout int       Timeout in seconds (default 300)

# Status command
decian-agent status
```

### Configuration File

```yaml
agent:
  id: ""                    # Set during registration
  hostname: ""              # Override system hostname
  version: "1.0.0"          # Agent version
  dry_run: false            # Don't submit results

dashboard:
  url: ""                   # Dashboard API URL (required)
  timeout: 30               # Request timeout in seconds

auth:
  token: ""                 # JWT token (required)

assessment:
  default_modules:          # Modules to run by default
    - "WIN_UPDATE_CHECK"
    - "WIN_FIREWALL_STATUS_CHECK"
  module_config: {}         # Module-specific settings

logging:
  verbose: false            # Enable debug logging
  level: "info"             # Log level
  file: ""                  # Log file path (optional)
```

## Security Considerations

- **Administrator Privileges**: Some modules require administrator privileges for comprehensive security checks
- **Network Access**: Agent needs HTTPS access to dashboard API
- **Token Security**: Store authentication tokens securely and rotate regularly
- **Audit Logging**: All agent activities are logged for security auditing

## Troubleshooting

### Common Issues

1. **Agent Registration Fails**
   - Verify dashboard URL is accessible
   - Check authentication token validity
   - Ensure network connectivity

2. **Module Execution Errors**
   - Run with `--verbose` flag for detailed logs
   - Check if administrator privileges are required
   - Verify PowerShell execution policy allows scripts

3. **Connection Timeouts**
   - Increase timeout in configuration
   - Check firewall and network settings
   - Verify dashboard availability

### Debug Mode

Enable verbose logging for troubleshooting:
```bash
decian-agent run --verbose
```

Or set in configuration:
```yaml
logging:
  verbose: true
  level: "debug"
```

## Development

### Building

```bash
# Build for current platform
go build -o decian-agent.exe .

# Build for Windows from other platforms
GOOS=windows GOARCH=amd64 go build -o decian-agent.exe .

# Run tests
go test ./...
```

### Adding New Modules

1. Implement the `Module` interface in `internal/modules/`
2. Register the module in `runner.go`
3. Add to available modules list
4. Update documentation

### Project Structure

```
agents/
├── main.go                 # Application entry point
├── go.mod                  # Go module definition
├── cmd/                    # CLI commands
│   ├── root.go            # Root command setup
│   ├── register.go        # Agent registration
│   ├── run.go             # Assessment execution
│   └── status.go          # Status checking
└── internal/              # Internal packages
    ├── config/            # Configuration management
    ├── logger/            # Logging utilities
    ├── client/            # Dashboard API client
    └── modules/           # Assessment modules
        ├── types.go       # Common types
        ├── runner.go      # Module execution
        └── *.go           # Individual modules
```

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Support

For support and documentation, visit the [Decian Documentation](https://docs.decian.com) or contact support@decian.com.