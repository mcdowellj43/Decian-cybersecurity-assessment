package modules

import (
	"decian-agent/internal/logger"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// MisconfigurationDiscoveryModule implements misconfiguration discovery assessment
type MisconfigurationDiscoveryModule struct {
	logger *logger.Logger
}

// NewMisconfigurationDiscoveryModule creates a new misconfiguration discovery module
func NewMisconfigurationDiscoveryModule(logger *logger.Logger) Module {
	return &MisconfigurationDiscoveryModule{
		logger: logger,
	}
}

// Info returns information about the module
func (m *MisconfigurationDiscoveryModule) Info() ModuleInfo {
	return ModuleInfo{
		Name:             "Misconfiguration Discovery",
		Description:      "Scan for risky configurations such as open RDP, permissive firewall rules, guest accounts, insecure protocols",
		CheckType:        CheckTypeMisconfigurationDiscovery,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelHigh,
		RequiresAdmin:    true,
	}
}

// Validate checks if the module can run in the current environment
func (m *MisconfigurationDiscoveryModule) Validate() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("this module only runs on Windows")
	}
	return nil
}

// Execute runs the misconfiguration discovery assessment
func (m *MisconfigurationDiscoveryModule) Execute() (*AssessmentResult, error) {
	m.logger.Info("Starting misconfiguration discovery assessment")

	result := &AssessmentResult{
		CheckType: CheckTypeMisconfigurationDiscovery,
		Data:      make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	var findings []map[string]interface{}
	riskScore := 0.0

	// Check for open RDP
	rdpFindings, rdpRisk := m.checkRDPConfiguration()
	if len(rdpFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Remote Desktop",
			"findings": rdpFindings,
		})
		riskScore += rdpRisk
	}

	// Check firewall configuration
	fwFindings, fwRisk := m.checkFirewallConfiguration()
	if len(fwFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Firewall",
			"findings": fwFindings,
		})
		riskScore += fwRisk
	}

	// Check guest account status
	guestFindings, guestRisk := m.checkGuestAccountConfiguration()
	if len(guestFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "User Accounts",
			"findings": guestFindings,
		})
		riskScore += guestRisk
	}

	// Check for insecure protocols
	protocolFindings, protocolRisk := m.checkInsecureProtocols()
	if len(protocolFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Network Protocols",
			"findings": protocolFindings,
		})
		riskScore += protocolRisk
	}

	// Check network shares
	shareFindings, shareRisk := m.checkNetworkShares()
	if len(shareFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Network Shares",
			"findings": shareFindings,
		})
		riskScore += shareRisk
	}

	// Cap risk score at 100
	if riskScore > 100 {
		riskScore = 100
	}

	result.Data["findings"] = findings
	result.Data["total_issues"] = len(findings)
	result.RiskScore = riskScore
	result.RiskLevel = DetermineRiskLevel(riskScore)

	m.logger.Info("Misconfiguration discovery completed", map[string]interface{}{
		"findings_count": len(findings),
		"risk_score":     riskScore,
		"risk_level":     result.RiskLevel,
	})

	return result, nil
}

// checkRDPConfiguration checks Remote Desktop configuration
func (m *MisconfigurationDiscoveryModule) checkRDPConfiguration() ([]string, float64) {
	var findings []string
	var risk float64

	// Check if RDP is enabled
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Terminal Server`, registry.QUERY_VALUE)
	if err != nil {
		m.logger.Warn("Failed to open Terminal Server registry key", map[string]interface{}{
			"error": err.Error(),
		})
		return findings, risk
	}
	defer key.Close()

	// Check fDenyTSConnections value
	denyConnections, _, err := key.GetIntegerValue("fDenyTSConnections")
	if err == nil && denyConnections == 0 {
		findings = append(findings, "Remote Desktop is enabled")
		risk += 25.0

		// Check if Network Level Authentication is enabled
		nlaKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, registry.QUERY_VALUE)
		if err == nil {
			defer nlaKey.Close()
			nla, _, err := nlaKey.GetIntegerValue("UserAuthentication")
			if err == nil && nla == 0 {
				findings = append(findings, "Network Level Authentication is disabled for RDP")
				risk += 15.0
			}
		}

		// Check for default RDP port
		portKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\Tds\tcp`, registry.QUERY_VALUE)
		if err == nil {
			defer portKey.Close()
			port, _, err := portKey.GetIntegerValue("PortNumber")
			if err == nil && port == 3389 {
				findings = append(findings, "RDP is using default port 3389")
				risk += 10.0
			}
		}
	}

	return findings, risk
}

// checkFirewallConfiguration checks Windows Firewall configuration
func (m *MisconfigurationDiscoveryModule) checkFirewallConfiguration() ([]string, float64) {
	var findings []string
	var risk float64

	// Check firewall profiles
	profiles := []string{"Domain", "Private", "Public"}
	for _, profile := range profiles {
		keyPath := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\%sProfile`, profile)
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		defer key.Close()

		// Check if firewall is enabled
		enabled, _, err := key.GetIntegerValue("EnableFirewall")
		if err == nil && enabled == 0 {
			findings = append(findings, fmt.Sprintf("Windows Firewall is disabled for %s profile", profile))
			risk += 20.0
		}

		// Check default inbound action
		inboundAction, _, err := key.GetIntegerValue("DefaultInboundAction")
		if err == nil && inboundAction == 0 {
			findings = append(findings, fmt.Sprintf("Default inbound action is Allow for %s profile", profile))
			risk += 15.0
		}
	}

	return findings, risk
}

// checkGuestAccountConfiguration checks guest account settings
func (m *MisconfigurationDiscoveryModule) checkGuestAccountConfiguration() ([]string, float64) {
	var findings []string
	var risk float64

	// Check guest account status
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SAM\SAM\Domains\Account\Users\000001F5`, registry.QUERY_VALUE)
	if err != nil {
		// Try alternative method using security policy
		return m.checkGuestAccountAlternative()
	}
	defer key.Close()

	// Check if guest account is enabled (simplified check)
	f, _, err := key.GetIntegerValue("F")
	if err == nil {
		// Guest account enabled if bit 1 of F register is not set
		if f&0x0002 == 0 {
			findings = append(findings, "Guest account is enabled")
			risk += 30.0
		}
	}

	return findings, risk
}

// checkGuestAccountAlternative uses alternative method to check guest account
func (m *MisconfigurationDiscoveryModule) checkGuestAccountAlternative() ([]string, float64) {
	var findings []string
	var risk float64

	// Check using LSA policy
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
	if err != nil {
		return findings, risk
	}
	defer key.Close()

	// Check for guest account restrictions
	restrictAnonymous, _, err := key.GetIntegerValue("RestrictAnonymous")
	if err == nil && restrictAnonymous == 0 {
		findings = append(findings, "Anonymous access is not restricted")
		risk += 15.0
	}

	return findings, risk
}

// checkInsecureProtocols checks for insecure network protocols
func (m *MisconfigurationDiscoveryModule) checkInsecureProtocols() ([]string, float64) {
	var findings []string
	var risk float64

	// Check SMBv1
	smbKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, registry.QUERY_VALUE)
	if err == nil {
		defer smbKey.Close()
		smb1, _, err := smbKey.GetIntegerValue("SMB1")
		if err == nil && smb1 == 1 {
			findings = append(findings, "SMBv1 protocol is enabled")
			risk += 25.0
		}
	}

	// Check for weak TLS/SSL protocols
	tlsKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols`, registry.QUERY_VALUE)
	if err == nil {
		defer tlsKey.Close()

		// Check for TLS 1.0
		tls10Key, err := registry.OpenKey(tlsKey, `TLS 1.0\Server`, registry.QUERY_VALUE)
		if err == nil {
			defer tls10Key.Close()
			enabled, _, err := tls10Key.GetIntegerValue("Enabled")
			if err == nil && enabled == 1 {
				findings = append(findings, "TLS 1.0 is enabled (insecure)")
				risk += 20.0
			}
		}

		// Check for SSL 3.0
		ssl30Key, err := registry.OpenKey(tlsKey, `SSL 3.0\Server`, registry.QUERY_VALUE)
		if err == nil {
			defer ssl30Key.Close()
			enabled, _, err := ssl30Key.GetIntegerValue("Enabled")
			if err == nil && enabled == 1 {
				findings = append(findings, "SSL 3.0 is enabled (insecure)")
				risk += 30.0
			}
		}
	}

	return findings, risk
}

// checkNetworkShares checks for risky network share configurations
func (m *MisconfigurationDiscoveryModule) checkNetworkShares() ([]string, float64) {
	var findings []string
	var risk float64

	// Check for administrative shares
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		return findings, risk
	}
	defer key.Close()

	// Check if administrative shares are enabled
	autoShareWks, _, err := key.GetIntegerValue("AutoShareWks")
	if err == nil && autoShareWks == 1 {
		findings = append(findings, "Administrative shares (C$, ADMIN$) are enabled")
		risk += 15.0
	}

	// Check null session shares
	nullSessionShares, _, err := key.GetStringValue("NullSessionShares")
	if err == nil && nullSessionShares != "" {
		shareList := strings.Split(nullSessionShares, "\x00")
		if len(shareList) > 1 { // More than just empty string
			findings = append(findings, fmt.Sprintf("Null session shares are configured: %v", shareList))
			risk += 20.0
		}
	}

	return findings, risk
}