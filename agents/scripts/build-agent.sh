#!/bin/bash

# Bash script to build organization-specific agent executables
# Usage: ./build-agent.sh --org-id "org123" --dashboard-url "https://dashboard.company.com" --output-dir "dist"

set -e

# Default values
OUTPUT_DIR="dist"
AGENT_VERSION="2.0.0"
BUILD_MODE="release"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --org-id)
            ORG_ID="$2"
            shift 2
            ;;
        --dashboard-url)
            DASHBOARD_URL="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --agent-version)
            AGENT_VERSION="$2"
            shift 2
            ;;
        --build-mode)
            BUILD_MODE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 --org-id ORG_ID --dashboard-url DASHBOARD_URL [OPTIONS]"
            echo ""
            echo "Required:"
            echo "  --org-id ORG_ID              Organization ID for the agent"
            echo "  --dashboard-url DASHBOARD_URL Dashboard URL for the agent"
            echo ""
            echo "Options:"
            echo "  --output-dir OUTPUT_DIR       Output directory (default: dist)"
            echo "  --agent-version VERSION       Agent version (default: 2.0.0)"
            echo "  --build-mode MODE            Build mode: debug|release (default: release)"
            echo "  -h, --help                   Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ -z "$ORG_ID" ]]; then
    echo "Error: --org-id is required"
    exit 1
fi

if [[ -z "$DASHBOARD_URL" ]]; then
    echo "Error: --dashboard-url is required"
    exit 1
fi

echo "🔨 Building Decian Security Agent"
echo "================================="
echo "Organization ID: $ORG_ID"
echo "Dashboard URL: $DASHBOARD_URL"
echo "Output Directory: $OUTPUT_DIR"
echo "Agent Version: $AGENT_VERSION"
echo

# Get script directory and change to agent directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
AGENT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$AGENT_DIR"

# Create output directory
if [[ ! -d "$OUTPUT_DIR" ]]; then
    echo "📁 Creating output directory..."
    mkdir -p "$OUTPUT_DIR"
fi

# Create organization-specific configuration
cat > internal/embedded/agent-config.yaml << EOF
# Decian Security Agent Configuration
# Organization: $ORG_ID
dashboard:
  url: "$DASHBOARD_URL"
  organization_id: "$ORG_ID"

agent:
  version: "$AGENT_VERSION"
  timeout: 300
  log_level: "INFO"

modules:
  - "MISCONFIGURATION_DISCOVERY"
  - "WEAK_PASSWORD_DETECTION"
  - "DATA_EXPOSURE_CHECK"
  - "PHISHING_EXPOSURE_INDICATORS"
  - "PATCH_UPDATE_STATUS"
  - "ELEVATED_PERMISSIONS_REPORT"
  - "EXCESSIVE_SHARING_RISKS"
  - "PASSWORD_POLICY_WEAKNESS"
  - "OPEN_SERVICE_PORT_ID"
  - "USER_BEHAVIOR_RISK_SIGNALS"

security:
  tls_version: "1.3"
  certificate_pinning: true
  encryption: true
  hmac_validation: true

settings:
  retry_attempts: 3
  retry_delay: "5s"
  heartbeat_interval: "60s"
EOF

echo "📝 Creating organization-specific configuration..."
echo "   ✅ Configuration written to internal/embedded/agent-config.yaml"

# Build the executable
EXE_NAME="decian-agent-$ORG_ID.exe"
EXE_PATH="$OUTPUT_DIR/$EXE_NAME"

echo "🔨 Building executable..."
echo "   Target: $EXE_PATH"

# Set build variables
export GOOS=windows
export GOARCH=amd64
export CGO_ENABLED=0

# Build flags for optimization
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS="-s -w -X main.version=$AGENT_VERSION -X main.buildTime=$BUILD_TIME -X main.orgId=$ORG_ID"

if [[ "$BUILD_MODE" == "release" ]]; then
    BUILD_FLAGS="-ldflags \"$LDFLAGS\" -trimpath"
else
    BUILD_FLAGS="-ldflags \"$LDFLAGS\""
fi

echo "   Command: go build -o $EXE_PATH $BUILD_FLAGS ."

# Execute build
go build -o "$EXE_PATH" $BUILD_FLAGS .

if [[ $? -eq 0 ]]; then
    echo "   ✅ Build successful!"

    # Check file size
    if command -v stat >/dev/null 2>&1; then
        FILE_SIZE=$(stat -f%z "$EXE_PATH" 2>/dev/null || stat -c%s "$EXE_PATH" 2>/dev/null || echo "unknown")
        if [[ "$FILE_SIZE" != "unknown" ]]; then
            FILE_SIZE_MB=$(echo "scale=2; $FILE_SIZE / 1024 / 1024" | bc -l 2>/dev/null || echo "unknown")
            echo "   📊 Executable size: ${FILE_SIZE_MB} MB"
        fi
    fi

    echo
    echo "🎉 Agent Build Complete!"
    echo "========================"
    echo "Executable: $EXE_PATH"
    echo "Organization: $ORG_ID"
    echo "Dashboard: $DASHBOARD_URL"
    echo
    echo "Distribution Instructions:"
    echo "1. Provide the executable to the target organization"
    echo "2. User runs: $EXE_NAME setup"
    echo "3. User runs: $EXE_NAME run"

else
    echo "   ❌ Build failed!"
    exit 1
fi

echo