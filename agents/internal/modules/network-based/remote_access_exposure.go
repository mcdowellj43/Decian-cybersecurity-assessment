package networkbased

import (
	"crypto/tls"
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"fmt"
	"net"
	"strings"
	"time"
)

// RemoteAccessExposureModule discovers RDP/VNC/VPN endpoints and basic protections (e.g., RDP NLA heuristic)
type RemoteAccessExposureModule struct {
	logger *logger.Logger
	info   modules.ModuleInfo
}

// NewRemoteAccessExposureModule creates a new instance
func NewRemoteAccessExposureModule(logger *logger.Logger) *RemoteAccessExposureModule {
	return &RemoteAccessExposureModule{
		logger: logger,
		info: modules.ModuleInfo{
			Name:             "RDP & Remote Access Exposure",
			Description:      "Identifies exposed remote-access services (RDP, VNC, common VPN portals) and detects basic protection signals such as RDP NLA",
			CheckType:        "REMOTE_ACCESS_EXPOSURE",
			Platform:         "windows",
			DefaultRiskLevel: "HIGH",
			RequiresAdmin:    false,
			Category:         modules.CategoryNetworkBased,
		},
	}
}

// GetInfo returns information about the module
func (m *RemoteAccessExposureModule) GetInfo() modules.ModuleInfo {
	return m.info
}

// Execute performs the remote-access exposure assessment
func (m *RemoteAccessExposureModule) Execute() (*modules.AssessmentResult, error) {
	m.logger.Info("Starting remote access exposure check", nil)
	start := time.Now()

	targets, err := m.getTargetHosts()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate targets: %w", err)
	}

	findings := []map[string]interface{}{}
	for _, host := range targets {
		// RDP (3389): check TCP reachability; attempt TLS handshake as a heuristic for NLA
		if m.portOpen(host, 3389, 1200*time.Millisecond) {
			nla := m.heuristicRdpNLA(host)
			sev := "MEDIUM"
			issue := "RDP exposed"
			if !nla {
				sev = "HIGH"
				issue = "RDP exposed without clear NLA support (heuristic)"
			}
			findings = append(findings, map[string]interface{}{
				"host":        host,
				"port":        3389,
				"service":     "RDP",
				"issue":       issue,
				"severity":    sev,
				"evidence":    fmt.Sprintf("tcp/3389 reachable; tls_hello=%v", nla),
				"remediation": "Place RDP behind a gateway/VPN, require NLA, enforce MFA, and restrict to management VLANs.",
				"timestamp":   time.Now(),
			})
		}

		// VNC (5900): banner-based detection (RFB)
		if m.portOpen(host, 5900, 1000*time.Millisecond) {
			banner := m.readBanner(host, 5900, 512, 1000*time.Millisecond)
			if strings.HasPrefix(banner, "RFB ") {
				findings = append(findings, map[string]interface{}{
					"host":        host,
					"port":        5900,
					"service":     "VNC",
					"issue":       "VNC server exposed",
					"severity":    "HIGH",
					"evidence":    strings.TrimSpace(banner),
					"remediation": "Disable public VNC; require VPN + strong auth; prefer secure remote-access tools with MFA.",
					"timestamp":   time.Now(),
				})
			} else if banner != "" {
				findings = append(findings, map[string]interface{}{
					"host":        host,
					"port":        5900,
					"service":     "VNC-like",
					"issue":       "Remote desktop-like port responded",
					"severity":    "MEDIUM",
					"evidence":    strings.TrimSpace(banner),
					"remediation": "Validate service; if VNC, disable or restrict; ensure encryption and MFA.",
					"timestamp":   time.Now(),
				})
			}
		}

		// VPN indicators (best-effort, non-intrusive):
		// - HTTPS portal on 443 with vendor strings in certificate subjects/organization
		if m.portOpen(host, 443, 1000*time.Millisecond) {
			vendor := m.inspectTLSCert(host, 443, 1500*time.Millisecond)
			if vendor != "" {
				findings = append(findings, map[string]interface{}{
					"host":        host,
					"port":        443,
					"service":     "HTTPS VPN Portal",
					"issue":       "Potential VPN portal exposed",
					"severity":    "MEDIUM",
					"evidence":    vendor,
					"remediation": "Restrict portal exposure; require MFA; limit to known source IPs or private access.",
					"timestamp":   time.Now(),
				})
			}
		}

		// PPTP (1723) - deprecated VPN protocol
		if m.portOpen(host, 1723, 1000*time.Millisecond) {
			findings = append(findings, map[string]interface{}{
				"host":        host,
				"port":        1723,
				"service":     "PPTP",
				"issue":       "Deprecated PPTP VPN service exposed",
				"severity":    "HIGH",
				"evidence":    "tcp/1723 reachable",
				"remediation": "Decommission PPTP; use modern VPN with strong ciphers and MFA (e.g., IKEv2 or TLS-based).",
				"timestamp":   time.Now(),
			})
		}
	}

	// Scoring: exposed RDP w/o NLA and VNC/PPTP weigh higher
	score := m.score(findings)
	level := modules.DetermineRiskLevel(score)

	result := &modules.AssessmentResult{
		CheckType: m.info.CheckType,
		RiskScore: score,
		RiskLevel: level,
		Data: map[string]interface{}{
			"summary":  m.summary(findings),
			"findings": findings,
			"recommendations": []string{
				"Put remote access behind a gateway/VPN and require MFA.",
				"Enable RDP NLA and limit access to management subnets only.",
				"Disable legacy services (VNC without encryption, PPTP).",
				"Forward remote-access logs to SIEM for alerting.",
			},
			"metrics": map[string]interface{}{
				"hosts_scanned": len(targets),
				"execution_ms":  time.Since(start).Milliseconds(),
			},
		},
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}
	return result, nil
}

// Validate checks if the module can run
func (m *RemoteAccessExposureModule) Validate() error {
	_, err := net.Interfaces()
	return err
}

// ---------- Helpers ----------

func (m *RemoteAccessExposureModule) getTargetHosts() ([]string, error) {
	// Enumerate local IPv4 /24s and generate a small target set (best-effort, capped)
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	hostset := map[string]struct{}{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			ip := ipn.IP.Mask(ipn.Mask)
			maskOnes, _ := ipn.Mask.Size()
			// Limit to reasonable local networks
			if maskOnes < 20 || maskOnes > 30 {
				continue
			}
			// Walk a handful of hosts in the subnet
			count := 0
			for h := IncIP(ip.Mask(ipn.Mask)); ipn.Contains(h) && count < 32; h = IncIP(h) { // cap 32 per iface
				hs := h.String()
				if hs == ip.String() {
					continue
				}
				hostset[hs] = struct{}{}
				count++
			}
		}
	}
	out := make([]string, 0, len(hostset))
	for h := range hostset {
		out = append(out, h)
		if len(out) >= 100 {
			break
		}
	}
	return out, nil
}


func (m *RemoteAccessExposureModule) portOpen(host string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		_ = c.Close()
		return true
	}
	return false
}

func (m *RemoteAccessExposureModule) readBanner(host string, port int, max int, timeout time.Duration) string {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, max)
	n, _ := c.Read(buf)
	if n > 0 {
		return string(buf[:n])
	}
	return ""
}

// heuristicRdpNLA: try TLS handshake to 3389; many NLA-enabled servers accept TLS (CredSSP) first.
// If TLS handshake succeeds, we mark nla=true (heuristic, not definitive).
func (m *RemoteAccessExposureModule) heuristicRdpNLA(host string) bool {
	addr := net.JoinHostPort(host, "3389")
	dial := &net.Dialer{Timeout: 1200 * time.Millisecond}
	conf := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	c, err := tls.DialWithDialer(dial, "tcp", addr, conf)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func (m *RemoteAccessExposureModule) inspectTLSCert(host string, port int, timeout time.Duration) string {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dial := &net.Dialer{Timeout: timeout}
	conf := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	c, err := tls.DialWithDialer(dial, "tcp", addr, conf)
	if err != nil {
		return ""
	}
	defer c.Close()
	cs := c.ConnectionState()
	vendors := []string{"GlobalProtect", "Pulse Secure", "Fortinet", "FortiGate", "AnyConnect", "Cisco", "Palo Alto", "OpenVPN", "Sophos", "WatchGuard"}
	for _, cert := range cs.PeerCertificates {
		sub := cert.Subject.String() + " " + cert.Issuer.String()
		for _, v := range vendors {
			if strings.Contains(strings.ToLower(sub), strings.ToLower(v)) {
				return fmt.Sprintf("Certificate matched vendor keyword: %s; Subject=%s; Issuer=%s", v, cert.Subject.CommonName, cert.Issuer.CommonName)
			}
		}
	}
	return ""
}

func (m *RemoteAccessExposureModule) score(findings []map[string]interface{}) float64 {
	score := 0.0
	for _, f := range findings {
		switch strings.ToUpper(fmt.Sprint(f["severity"])) {
		case "HIGH":
			score += 20
		case "MEDIUM":
			score += 10
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

func (m *RemoteAccessExposureModule) summary(findings []map[string]interface{}) string {
	if len(findings) == 0 {
		return "No remote-access exposures were detected on scanned hosts."
	}
	rdpNoNLA, vnc, pptp := 0, 0, 0
	for _, f := range findings {
		svc := strings.ToUpper(fmt.Sprint(f["service"]))
		sev := strings.ToUpper(fmt.Sprint(f["severity"]))
		if svc == "RDP" && sev == "HIGH" {
			rdpNoNLA++
		}
		if svc == "VNC" {
			vnc++
		}
		if svc == "PPTP" {
			pptp++
		}
	}
	return fmt.Sprintf("Detected %d RDP endpoints without clear NLA (heuristic), %d VNC services, and %d PPTP endpoints.", rdpNoNLA, vnc, pptp)
}

// Plugin constructor (Required)
func NewRemoteAccessExposureModulePlugin(logger *logger.Logger) modules.ModulePlugin {
	return NewRemoteAccessExposureModule(logger)
}

// Auto-registration (Required)
func init() {
	modules.RegisterPluginConstructor("REMOTE_ACCESS_EXPOSURE", NewRemoteAccessExposureModulePlugin)
}
