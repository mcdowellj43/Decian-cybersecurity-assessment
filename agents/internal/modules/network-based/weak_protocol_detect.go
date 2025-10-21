package networkbased

import (
	"crypto/tls"
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WeakProtocolDetectionModule implements weak/legacy protocol discovery over the network
type WeakProtocolDetectionModule struct {
	logger *logger.Logger
	info   modules.ModuleInfo
	modules.TargetAware
}

// WeakProtocolFinding represents a single weak-protocol observation
type WeakProtocolFinding struct {
	Host           string            `json:"host"`
	Port           int               `json:"port"`
	Service        string            `json:"service"`
	Protocol       string            `json:"protocol"`
	Issue          string            `json:"issue"`
	Severity       string            `json:"severity"`
	Evidence       string            `json:"evidence"`
	Recommendation string            `json:"recommendation"`
	Timestamp      time.Time         `json:"timestamp"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// WeakProtocolScanResult aggregates all weak-protocol results
type WeakProtocolScanResult struct {
	TotalHosts     int                   `json:"total_hosts"`
	HostsScanned   []string              `json:"hosts_scanned"`
	Findings       []WeakProtocolFinding `json:"findings"`
	ScanDuration   time.Duration         `json:"scan_duration"`
	TestedTLSPorts []int                 `json:"tested_tls_ports"`
	Metrics        map[string]any        `json:"metrics"`
}

// NewWeakProtocolDetectionModule creates a new instance
func NewWeakProtocolDetectionModule(logger *logger.Logger) *WeakProtocolDetectionModule {
	return &WeakProtocolDetectionModule{
		logger: logger,
		info: modules.ModuleInfo{
			Name:             "Weak Protocol Detection",
			Description:      "Detects legacy or unencrypted services (e.g., Telnet/FTP/LDAP), plaintext protocols, and outdated TLS versions accepted by services",
			CheckType:        "WEAK_PROTOCOL_DETECTION",
			Platform:         "windows",
			DefaultRiskLevel: "HIGH",
			RequiresAdmin:    false,
			Category:         modules.CategoryNetworkBased,
		},
	}
}

// GetInfo returns information about the module
func (m *WeakProtocolDetectionModule) GetInfo() modules.ModuleInfo {
	return m.info
}

// Execute performs the weak protocol detection assessment
func (m *WeakProtocolDetectionModule) Execute() (*modules.AssessmentResult, error) {
	m.logger.Info("Starting weak protocol detection", nil)
	start := time.Now()

	// Get target hosts - use target context if available, otherwise auto-discover
	var hosts []string
	var err error

	target := m.Target()
	if target.IP != "" {
		// Use specific target IP from job context
		hosts = []string{target.IP}
		m.logger.Debug("Using target IP from context", map[string]interface{}{"target": target.IP})
	} else {
		// Fall back to auto-discovery for backward compatibility
		hosts, err = m.getTargetHosts()
		if err != nil {
			return nil, fmt.Errorf("failed to determine target hosts: %w", err)
		}
		m.logger.Debug("Auto-discovered target hosts", map[string]interface{}{"count": len(hosts)})
	}

	result, err := m.scanWeakProtocols(hosts)
	if err != nil {
		return nil, fmt.Errorf("weak protocol scan failed: %w", err)
	}
	result.ScanDuration = time.Since(start)

	// Calculate risk and produce summary/recommendations
	riskScore := m.calculateRiskScore(result.Findings, len(result.HostsScanned))
	riskLevel := modules.DetermineRiskLevel(riskScore)
	summary := m.generateSummary(result)
	recommendations := m.generateRecommendations(result)

	out := &modules.AssessmentResult{
		CheckType: m.info.CheckType,
		RiskScore: riskScore,
		RiskLevel: riskLevel,
		Data: map[string]interface{}{
			"scan_result":     result,
			"summary":         summary,
			"recommendations": recommendations,
			"metrics":         result.Metrics,
		},
		Timestamp: time.Now(),
		Duration:  result.ScanDuration,
	}

	m.logger.Info("Weak protocol detection completed", map[string]interface{}{
		"duration":       result.ScanDuration.String(),
		"hosts_scanned":  len(result.HostsScanned),
		"findings_count": len(result.Findings),
		"risk_score":     riskScore,
	})

	return out, nil
}

// Validate checks if the module can run on this system
func (m *WeakProtocolDetectionModule) Validate() error {
	// Basic network capability check
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) == 0 {
		return fmt.Errorf("cannot enumerate network interfaces: %w", err)
	}
	// Quick TCP dial capability probe (expected to succeed/fail harmlessly)
	_ = func() error {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:0", 1*time.Second)
		if err == nil {
			conn.Close()
		}
		return nil
	}()
	return nil
}

// scanWeakProtocols scans hosts for weak/legacy protocols and outdated TLS
func (m *WeakProtocolDetectionModule) scanWeakProtocols(hosts []string) (*WeakProtocolScanResult, error) {
	// Plain/legacy services to probe via TCP connect + optional banner peek
	plainChecks := []struct {
		port         int
		service      string
		protocol     string
		issue        string
		recommend    string
		severity     string
		probeMessage string // optional initial probe
	}{
		{21, "FTP", "TCP", "FTP allows plaintext credentials", "Disable or migrate to SFTP/FTPS; restrict access", "HIGH", ""},
		{23, "Telnet", "TCP", "Telnet allows plaintext remote access", "Disable Telnet; use SSH", "HIGH", ""},
		{25, "SMTP", "TCP", "SMTP service may accept plaintext auth", "Enforce STARTTLS and modern ciphers", "MEDIUM", "EHLO example\r\n"},
		{80, "HTTP", "TCP", "Unencrypted HTTP detected", "Redirect to HTTPS and enforce HSTS", "MEDIUM", "HEAD / HTTP/1.0\r\n\r\n"},
		{110, "POP3", "TCP", "POP3 may allow plaintext auth", "Use POP3S (995) and modern TLS", "MEDIUM", ""},
		{143, "IMAP", "TCP", "IMAP may allow plaintext auth", "Use IMAPS (993) and modern TLS", "MEDIUM", ""},
		{389, "LDAP", "TCP", "LDAP over plaintext (389) detected", "Use LDAPS (636) or StartTLS", "HIGH", ""},
		{139, "NetBIOS-SSN", "TCP", "Legacy SMB over NetBIOS (139) exposed", "Disable SMB1/NetBIOS over TCP; restrict SMB", "HIGH", ""},
		{445, "SMB", "TCP", "SMB service exposed (check SMB1 disabled)", "Ensure SMBv1 disabled; restrict SMB", "MEDIUM", ""},
		{5900, "VNC", "TCP", "VNC may lack strong auth/encryption", "Require strong auth; tunnel via SSH/VPN", "MEDIUM", ""},
		{8080, "HTTP-Alt", "TCP", "Alternate HTTP endpoint (unencrypted) detected", "Enforce TLS; restrict management ports", "LOW", "HEAD / HTTP/1.0\r\n\r\n"},
		{1433, "MSSQL", "TCP", "MSSQL may allow unencrypted logons", "Enforce TLS encryption; restrict exposure", "MEDIUM", ""},
		{3306, "MySQL", "TCP", "MySQL may allow unencrypted logons", "Require TLS and strong auth; restrict access", "MEDIUM", ""},
	}

	// TLS ports to test for outdated protocol acceptance (TLS1.0/1.1)
	tlsPorts := []int{443, 8443, 993, 995, 465, 636, 3389, 9443}

	result := &WeakProtocolScanResult{
		TotalHosts:     len(hosts),
		HostsScanned:   hosts,
		Findings:       []WeakProtocolFinding{},
		TestedTLSPorts: tlsPorts,
		Metrics:        map[string]any{},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 30) // limit concurrency

	// helper: record finding
	record := func(f WeakProtocolFinding) {
		mu.Lock()
		result.Findings = append(result.Findings, f)
		mu.Unlock()
	}

	for _, host := range hosts {
		h := host
		// quick reachability probe (optional): try a couple common ports
		if !m.quickReachable(h) {
			continue
		}

		// Plain protocol checks
		for _, chk := range plainChecks {
			wg.Add(1)
			go func(host string, c struct {
				port         int
				service      string
				protocol     string
				issue        string
				recommend    string
				severity     string
				probeMessage string
			}) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				addr := net.JoinHostPort(host, strconv.Itoa(c.port))
				conn, err := net.DialTimeout("tcp", addr, 1500*time.Millisecond)
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))

				// Optional tiny probe to elicit a banner
				var banner string
				if len(c.probeMessage) > 0 {
					_, _ = conn.Write([]byte(c.probeMessage))
				}
				buf := make([]byte, 512)
				n, _ := conn.Read(buf)
				if n > 0 {
					banner = strings.TrimSpace(string(buf[:n]))
				}

				record(WeakProtocolFinding{
					Host:           host,
					Port:           c.port,
					Service:        c.service,
					Protocol:       c.protocol,
					Issue:          c.issue,
					Severity:       c.severity,
					Evidence:       truncateEvidence(banner),
					Recommendation: c.recommend,
					Timestamp:      time.Now(),
				})
			}(h, chk)
		}

		// TLS version acceptance checks
		for _, p := range tlsPorts {
			wg.Add(1)
			go func(host string, port int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				addr := net.JoinHostPort(host, strconv.Itoa(port))

				// Test TLS 1.0
				if m.acceptsTLSVersion(addr, tls.VersionTLS10) {
					record(WeakProtocolFinding{
						Host:           host,
						Port:           port,
						Service:        "TLS Service",
						Protocol:       "TLS",
						Issue:          "Service accepts outdated TLS 1.0",
						Severity:       "HIGH",
						Evidence:       "Successful handshake with TLS 1.0",
						Recommendation: "Disable TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3)",
						Timestamp:      time.Now(),
					})
				} else if m.acceptsTLSVersion(addr, tls.VersionTLS11) {
					record(WeakProtocolFinding{
						Host:           host,
						Port:           port,
						Service:        "TLS Service",
						Protocol:       "TLS",
						Issue:          "Service accepts outdated TLS 1.1",
						Severity:       "MEDIUM",
						Evidence:       "Successful handshake with TLS 1.1",
						Recommendation: "Disable TLS 1.1; require TLS 1.2+ (prefer 1.3)",
						Timestamp:      time.Now(),
					})
				}
			}(h, p)
		}
	}

	wg.Wait()

	// Metrics
	result.Metrics["findings_count"] = len(result.Findings)
	result.Metrics["hosts_with_findings"] = m.countDistinctHosts(result.Findings)

	return result, nil
}

// quickReachable tries a few common ports to see if a host is alive
func (m *WeakProtocolDetectionModule) quickReachable(host string) bool {
	ports := []int{443, 80, 22, 3389, 445}
	for _, p := range ports {
		addr := net.JoinHostPort(host, strconv.Itoa(p))
		conn, err := net.DialTimeout("tcp", addr, 800*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}

// acceptsTLSVersion attempts a handshake with an exact TLS version
func (m *WeakProtocolDetectionModule) acceptsTLSVersion(address string, version uint16) bool {
	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond}
	cfg := &tls.Config{
		InsecureSkipVerify: true, // we only care about protocol acceptance
		MinVersion:         version,
		MaxVersion:         version,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, cfg)
	if err != nil {
		return false
	}
	defer conn.Close()
	if cs := conn.ConnectionState(); cs.Version == version {
		return true
	}
	return false
}

// calculateRiskScore gives weighted score (max 100)
func (m *WeakProtocolDetectionModule) calculateRiskScore(findings []WeakProtocolFinding, hosts int) float64 {
	if len(findings) == 0 {
		return 10.0
	}
	score := 0.0
	for _, f := range findings {
		switch strings.ToUpper(f.Severity) {
		case "HIGH":
			score += 10.0
		case "MEDIUM":
			score += 6.0
		default:
			score += 3.0
		}
	}
	// Normalize a bit by host count, cap at 100
	if hosts > 0 {
		score = score * (1.0 + 0.1*float64(m.countDistinctHosts(findings)))
	}
	if score > 100.0 {
		score = 100.0
	}
	return score
}

func (m *WeakProtocolDetectionModule) countDistinctHosts(findings []WeakProtocolFinding) int {
	seen := map[string]struct{}{}
	for _, f := range findings {
		seen[f.Host] = struct{}{}
	}
	return len(seen)
}

// generateSummary creates a human-readable summary
func (m *WeakProtocolDetectionModule) generateSummary(result *WeakProtocolScanResult) string {
	if len(result.Findings) == 0 {
		return "No weak or legacy protocols detected on scanned hosts"
	}

	high, med, low := 0, 0, 0
	for _, f := range result.Findings {
		switch strings.ToUpper(f.Severity) {
		case "HIGH":
			high++
		case "MEDIUM":
			med++
		default:
			low++
		}
	}

	return fmt.Sprintf(
		"Detected %d weak/legacy protocol exposures across %d hosts (High: %d, Medium: %d, Low: %d).",
		len(result.Findings), result.Metrics["hosts_with_findings"], high, med, low,
	)
}

// generateRecommendations creates actionable next-steps
func (m *WeakProtocolDetectionModule) generateRecommendations(result *WeakProtocolScanResult) []string {
	recs := []string{
		"Disable legacy plaintext services (Telnet, FTP, LDAP 389) and replace with encrypted alternatives (SSH/SFTP/LDAPS).",
		"Enforce TLS 1.2+ (prefer TLS 1.3) on all services; disable TLS 1.0/1.1.",
		"Restrict SMB exposure and ensure SMBv1 is disabled; limit access by network policy.",
		"Redirect HTTP to HTTPS and enable HSTS; ensure management interfaces require TLS.",
		"Limit service exposure with firewall rules and network segmentation.",
	}
	return recs
}

// ----------------------------------------------------------------------------
// Host discovery helpers (mirrors style from OSFingerprintingModule)
// ----------------------------------------------------------------------------

func (m *WeakProtocolDetectionModule) getTargetHosts() ([]string, error) {
	ranges, err := m.getLocalNetworkRanges()
	if err != nil {
		return nil, err
	}

	var all []string
	for _, cidr := range ranges {
		hosts, err := m.getHostsFromCIDR(cidr)
		if err != nil {
			m.logger.Warn("Failed to parse CIDR range", map[string]interface{}{
				"cidr":  cidr,
				"error": err.Error(),
			})
			continue
		}
		if len(hosts) > 50 {
			hosts = hosts[:50]
		}
		all = append(all, hosts...)
	}

	seen := make(map[string]bool)
	var unique []string
	for _, h := range all {
		if !seen[h] && len(unique) < 100 {
			seen[h] = true
			unique = append(unique, h)
		}
	}
	return unique, nil
}

func (m *WeakProtocolDetectionModule) getLocalNetworkRanges() ([]string, error) {
	var ranges []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			var mask net.IPMask
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				mask = v.Mask
			case *net.IPAddr:
				ip = v.IP
				mask = ip.DefaultMask()
			default:
				continue
			}
			if ip.To4() == nil {
				continue
			}
			network := ip.Mask(mask)
			ones, _ := mask.Size()
			if ones >= 16 && ones <= 24 {
				ranges = append(ranges, fmt.Sprintf("%s/%d", network.String(), ones))
			}
		}
	}
	if len(ranges) == 0 {
		ranges = []string{"192.168.1.0/24"}
	}
	return ranges, nil
}

func (m *WeakProtocolDetectionModule) getHostsFromCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ones, _ := ipNet.Mask.Size()
	if ones < 20 {
		return nil, fmt.Errorf("subnet too large for weak protocol scan")
	}

	var hosts []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); m.incrementIP(ip) {
		if !ip.Equal(ipNet.IP) && !ip.Equal(m.broadcastIP(ipNet)) {
			hosts = append(hosts, ip.String())
		}
		if len(hosts) >= 50 {
			break
		}
	}
	return hosts, nil
}

func (m *WeakProtocolDetectionModule) incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (m *WeakProtocolDetectionModule) broadcastIP(ipNet *net.IPNet) net.IP {
	b := make(net.IP, len(ipNet.IP))
	copy(b, ipNet.IP)
	for i := 0; i < len(b); i++ {
		b[i] |= ^ipNet.Mask[i]
	}
	return b
}

// ----------------------------------------------------------------------------
// Small helpers
// ----------------------------------------------------------------------------

func truncateEvidence(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > 240 {
		return s[:240] + "..."
	}
	return s
}

// Plugin constructor for auto-registration
func NewWeakProtocolDetectionModulePlugin(logger *logger.Logger) modules.ModulePlugin {
	return NewWeakProtocolDetectionModule(logger)
}

// Auto-registration via init() function
func init() {
	modules.RegisterPluginConstructor("WEAK_PROTOCOL_DETECTION", NewWeakProtocolDetectionModulePlugin)
}
