# PowerShell script to build organization-specific agent executables
# Usage: .\build-agent.ps1 -OrgId "org123" -DashboardUrl "https://dashboard.company.com" -OutputDir "dist"

param(
    [Parameter(Mandatory=$true)]
    [string]$OrgId,

    [Parameter(Mandatory=$true)]
    [string]$DashboardUrl,

    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "dist",

    [Parameter(Mandatory=$false)]
    [string]$AgentVersion = "2.0.0",

    [Parameter(Mandatory=$false)]
    [string]$BuildMode = "release"
)

Write-Host "Building Decian Security Agent" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
Write-Host "Organization ID: $OrgId" -ForegroundColor White
Write-Host "Dashboard URL: $DashboardUrl" -ForegroundColor White
Write-Host "Output Directory: $OutputDir" -ForegroundColor White
Write-Host "Agent Version: $AgentVersion" -ForegroundColor White
Write-Host

# Ensure we're in the correct directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentDir = Split-Path -Parent $ScriptDir
Push-Location $AgentDir

try {
    # Create output directory
    if (-not (Test-Path $OutputDir)) {
        Write-Host "Creating output directory..." -ForegroundColor Yellow
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    # Create organization-specific configuration
    $ConfigContent = @"
# Decian Security Agent Configuration
# Organization: $OrgId
dashboard:
  url: "$DashboardUrl"
  organization_id: "$OrgId"

agent:
  version: "$AgentVersion"
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
"@

    # Write configuration to embedded file
    $EmbeddedConfigPath = "internal\embedded\agent-config.yaml"
    Write-Host "Creating organization-specific configuration..." -ForegroundColor Yellow
    $ConfigContent | Out-File -FilePath $EmbeddedConfigPath -Encoding UTF8
    Write-Host "Configuration written to $EmbeddedConfigPath" -ForegroundColor Green

    # Build the executable
    $ExeName = "decian-agent-$OrgId.exe"
    $ExePath = Join-Path $OutputDir $ExeName

    Write-Host "Building executable..." -ForegroundColor Yellow
    Write-Host "Target: $ExePath" -ForegroundColor White

    # Set build variables
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"

    # Build flags for optimization
    $LdFlags = @(
        "-s",
        "-w",
        "-X main.version=$AgentVersion",
        "-X main.buildTime=$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')",
        "-X main.orgId=$OrgId"
    ) -join " "

    if ($BuildMode -eq "release") {
        $BuildFlags = @("-ldflags", $LdFlags, "-trimpath")
    } else {
        $BuildFlags = @("-ldflags", $LdFlags)
    }

    # Execute build
    $BuildArgs = @("build", "-o", $ExePath) + $BuildFlags + @(".")
    Write-Host "Command: go $($BuildArgs -join ' ')" -ForegroundColor Gray

    & go @BuildArgs

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Build successful!" -ForegroundColor Green

        # Check file size
        $FileInfo = Get-Item $ExePath
        $FileSizeMB = [math]::Round($FileInfo.Length / 1MB, 2)
        Write-Host "Executable size: $FileSizeMB MB" -ForegroundColor White

        Write-Host
        Write-Host "Agent Build Complete!" -ForegroundColor Green
        Write-Host "=====================" -ForegroundColor Green
        Write-Host "Executable: $ExePath" -ForegroundColor White
        Write-Host "Organization: $OrgId" -ForegroundColor White
        Write-Host "Dashboard: $DashboardUrl" -ForegroundColor White
        Write-Host
        Write-Host "Distribution Instructions:" -ForegroundColor Yellow
        Write-Host "1. Provide the executable to the target organization" -ForegroundColor White
        Write-Host "2. User runs: $ExeName setup" -ForegroundColor White
        Write-Host "3. User runs: $ExeName run" -ForegroundColor White

    } else {
        Write-Host "Build failed!" -ForegroundColor Red
        exit 1
    }

} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
} finally {
    Pop-Location
}

Write-Host