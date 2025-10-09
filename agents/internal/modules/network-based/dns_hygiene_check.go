package networkbased

import (
	"bufio"
	"bytes"
	"context"
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// DNSHygieneCheckModule checks for dangerous DNS behaviors (open recursion, AXFR, leakage)
type DNSHygieneCheckModule struct {
	logger *logger.Logger
	info   modules.ModuleInfo
	modules.TargetAware
}

// NewDNSHygieneCheckModule creates a new instance
func NewDNSHygieneCheckModule(logger *logger.Logger) *DNSHygieneCheckModule {
	return &DNSHygieneCheckModule{
		logger: logger,
		info: modules.ModuleInfo{
			Name:             "DNS Hygiene Check",
			Description:      "Checks internal DNS servers for open recursion, zone transfer (AXFR) exposure, and internal record leakage",
			CheckType:        "WEAK_DNS_HYGIENE",
			Platform:         "windows",
			DefaultRiskLevel: "HIGH",
			RequiresAdmin:    false,
			Category:         modules.CategoryNetworkBased,
		},
	}
}

// GetInfo returns information about the module
func (m *DNSHygieneCheckModule) GetInfo() modules.ModuleInfo {
	return m.info
}

// Execute performs the DNS hygiene assessment
func (m *DNSHygieneCheckModule) Execute() (*modules.AssessmentResult, error) {
	m.logger.Info("Starting DNS hygiene check", nil)
	start := time.Now()

	servers := m.getLocalDnsServers()
	if len(servers) == 0 {
		return &modules.AssessmentResult{
			CheckType: m.info.CheckType,
			RiskScore: 10,
			RiskLevel: modules.DetermineRiskLevel(10),
			Data: map[string]interface{}{
				"summary":  "No DNS servers discovered on this host",
				"findings": []map[string]interface{}{},
				"metrics":  map[string]interface{}{"execution_time": time.Since(start).String()},
			},
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, nil
	}

	candidateZone := m.deriveCandidateZone()
	findings := []map[string]interface{}{}
	totalProbed := 0

	for _, srv := range servers {
		s := strings.TrimSpace(srv)
		if net.ParseIP(s) == nil {
			continue
		}
		totalProbed++

		// 1) Open recursion check: ask this server to resolve a domain it is unlikely to host
		recFinding := m.checkOpenRecursion(s, "example.com")
		if recFinding != nil {
			findings = append(findings, recFinding)
		}

		// 2) Internal leakage probe: resolve a likely-internal hostname against this server
		if candidateZone != "" {
			hostToTry := "nonexistent-host." + candidateZone
			leakFinding := m.checkUnexpectedResolution(s, hostToTry)
			if leakFinding != nil {
				findings = append(findings, leakFinding)
			}
		}

		// 3) Conservative AXFR attempt (only if server appears local/RFC1918)
		if m.isRFC1918(s) && candidateZone != "" {
			axfrFinding := m.tryAXFR(s, candidateZone)
			if axfrFinding != nil {
				findings = append(findings, axfrFinding)
			}
		}
	}

	// Risk score: weight open recursion/AXFR higher than leakage probes
	score := m.calculateRisk(findings)
	level := modules.DetermineRiskLevel(score)

	summary := m.summarize(findings, totalProbed, candidateZone)
	reco := m.recommend(findings)

	result := &modules.AssessmentResult{
		CheckType: m.info.CheckType,
		RiskScore: score,
		RiskLevel: level,
		Data: map[string]interface{}{
			"summary":         summary,
			"findings":        findings,
			"recommendations": reco,
			"metrics": map[string]interface{}{
				"dns_servers_checked": len(servers),
				"candidate_zone":      candidateZone,
				"execution_time":      time.Since(start).String(),
			},
		},
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}

	return result, nil
}

// Validate checks if the module can run on this system
func (m *DNSHygieneCheckModule) Validate() error {
	// Basic test: ensure we can resolve locally at all
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_, err := net.DefaultResolver.LookupHost(ctx, "example.com")
	if err != nil {
		// Not fatal; return nil to allow local-server targeting anyway
		m.logger.Warn("Local resolver failed example.com lookup", map[string]interface{}{"error": err.Error()})
	}
	return nil
}

// ---------- Helpers ----------

func (m *DNSHygieneCheckModule) getLocalDnsServers() []string {
	// Parse "ipconfig /all" for DNS Servers lines (Windows)
	cmd := exec.Command("ipconfig", "/all")
	out, err := cmd.Output()
	if err != nil {
		m.logger.Warn("ipconfig /all failed, falling back to empty DNS server list", map[string]interface{}{"error": err.Error()})
		return []string{}
	}

	servers := []string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	reDNS := regexp.MustCompile(`(?i)^\s*DNS Servers(?:\s*\.\s*)*:\s*(.+)$`)

	var collecting bool
	for sc.Scan() {
		line := sc.Text()
		if m := reDNS.FindStringSubmatch(line); m != nil {
			first := strings.TrimSpace(m[1])
			if net.ParseIP(first) != nil {
				servers = append(servers, first)
				collecting = true
			}
			continue
		}
		// Continuation lines (indented)
		if collecting && strings.HasPrefix(line, "   ") {
			val := strings.TrimSpace(line)
			if net.ParseIP(val) != nil {
				servers = append(servers, val)
			} else {
				collecting = false
			}
		} else {
			collecting = false
		}
	}
	return uniqueStrings(servers)
}

func (m *DNSHygieneCheckModule) deriveCandidateZone() string {
	// Try USERDNSDOMAIN (Windows), else derive from FQDN, else empty
	if v := os.Getenv("USERDNSDOMAIN"); v != "" {
		return strings.ToLower(strings.Trim(v, "."))
	}
	hn, _ := os.Hostname()
	if hn != "" && strings.Contains(hn, ".") {
		parts := strings.SplitN(hn, ".", 2)
		if len(parts) == 2 {
			return strings.ToLower(strings.Trim(parts[1], "."))
		}
	}
	return ""
}

func (m *DNSHygieneCheckModule) checkOpenRecursion(server, domain string) map[string]interface{} {
	start := time.Now()
	ips, err := m.directLookupA(server, domain, 2*time.Second)
	elapsed := time.Since(start)

	// If we successfully resolve against a server that likely doesn't host the zone locally,
	// treat as potentially open recursion.
	if err == nil && len(ips) > 0 {
		return map[string]interface{}{
			"server":      server,
			"check":       "open_recursion",
			"issue":       "DNS server allows recursive resolution",
			"severity":    "HIGH",
			"evidence":    fmt.Sprintf("Resolved %s -> %v", domain, ips),
			"latency_ms":  elapsed.Milliseconds(),
			"remediation": "Disable recursion on authoritative servers or restrict recursion to internal subnets.",
			"timestamp":   time.Now(),
		}
	}

	// Not necessarily safe/closed, but no finding if failed/timeout
	return nil
}

func (m *DNSHygieneCheckModule) checkUnexpectedResolution(server, fqdn string) map[string]interface{} {
	start := time.Now()
	ips, err := m.directLookupA(server, fqdn, 2*time.Second)
	elapsed := time.Since(start)

	// If a clearly non-existent internal name returns a public IP, that’s suspicious leakage/misconfig.
	if err == nil && len(ips) > 0 {
		return map[string]interface{}{
			"server":      server,
			"check":       "internal_leak",
			"issue":       "Unexpected resolution for internal-style hostname",
			"severity":    "MEDIUM",
			"evidence":    fmt.Sprintf("Resolved %s -> %v", fqdn, ips),
			"latency_ms":  elapsed.Milliseconds(),
			"remediation": "Ensure split-horizon DNS is configured and internal zones are not leaked externally.",
			"timestamp":   time.Now(),
		}
	}
	return nil
}

func (m *DNSHygieneCheckModule) tryAXFR(server, zone string) map[string]interface{} {
	resp, rcode, err := m.axfrAttempt(server, zone, 1500*time.Millisecond)
	sev := "HIGH"
	issue := "DNS zone transfer (AXFR) permitted"
	if err != nil {
		// Only log as informational if clearly refused; otherwise, no finding
		if errors.Is(err, errAXFRRefused) {
			return map[string]interface{}{
				"server":      server,
				"check":       "axfr",
				"issue":       "Zone transfer refused (good)",
				"severity":    "INFO",
				"evidence":    fmt.Sprintf("RCODE=%d", rcode),
				"remediation": "Keep AXFR disabled or restrict via TSIG/IP ACLs.",
				"timestamp":   time.Now(),
			}
		}
		return nil
	}

	// If we got any data back (even partial), treat as high-risk
	return map[string]interface{}{
		"server":      server,
		"check":       "axfr",
		"issue":       issue,
		"severity":    sev,
		"evidence":    fmt.Sprintf("Received %d bytes during AXFR attempt", len(resp)),
		"remediation": "Disable zone transfers or restrict to authorized secondaries with TSIG and IP allowlists.",
		"timestamp":   time.Now(),
	}
}

// directLookupA does a single A lookup against a specific server using net.Resolver
func (m *DNSHygieneCheckModule) directLookupA(server, name string, timeout time.Duration) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ips, err := r.LookupHost(ctx, name)
	return ips, err
}

// Minimal AXFR attempt over TCP: send a basic DNS query (QTYPE=AXFR) and read first response
var errAXFRRefused = errors.New("axfr refused")

func (m *DNSHygieneCheckModule) axfrAttempt(server, zone string, timeout time.Duration) ([]byte, int, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server, "53"), timeout)
	if err != nil {
		return nil, -1, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	msg := buildDNSQueryAXFR(zone)
	if _, err := conn.Write(msg); err != nil {
		return nil, -1, err
	}

	// Read first TCP DNS response (length-prefixed)
	lenBuf := make([]byte, 2)
	if _, err := conn.Read(lenBuf); err != nil {
		return nil, -1, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf))
	if respLen <= 0 || respLen > 65535 {
		return nil, -1, fmt.Errorf("invalid dns length")
	}
	resp := make([]byte, respLen)
	n, err := ioReadFull(conn, resp)
	if err != nil || n != respLen {
		return nil, -1, err
	}

	// Parse header flags/rcode minimally
	if respLen < 12 {
		return resp, -1, nil
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	rcode := int(flags & 0x000F)
	if rcode == 5 { // REFUSED
		return nil, rcode, errAXFRRefused
	}
	// Any other answer means something came back
	return resp, rcode, nil
}

func buildDNSQueryAXFR(zone string) []byte {
	// Build a minimal DNS message: ID=0x1234, RD=0, QD=1, QTYPE=AXFR(252), QCLASS=IN(1)
	var body bytes.Buffer
	// Header
	binary.Write(&body, binary.BigEndian, uint16(0x1234)) // ID
	binary.Write(&body, binary.BigEndian, uint16(0x0100)) // Flags: standard query
	binary.Write(&body, binary.BigEndian, uint16(1))      // QDCOUNT
	binary.Write(&body, binary.BigEndian, uint16(0))      // ANCOUNT
	binary.Write(&body, binary.BigEndian, uint16(0))      // NSCOUNT
	binary.Write(&body, binary.BigEndian, uint16(0))      // ARCOUNT

	// Question (QNAME)
	labels := strings.Split(strings.Trim(zone, "."), ".")
	for _, lab := range labels {
		if lab == "" {
			continue
		}
		body.WriteByte(byte(len(lab)))
		body.WriteString(lab)
	}
	body.WriteByte(0x00)                               // terminator
	binary.Write(&body, binary.BigEndian, uint16(252)) // QTYPE AXFR
	binary.Write(&body, binary.BigEndian, uint16(1))   // QCLASS IN

	// TCP length prefix
	raw := body.Bytes()
	var pkt bytes.Buffer
	binary.Write(&pkt, binary.BigEndian, uint16(len(raw)))
	pkt.Write(raw)
	return pkt.Bytes()
}

func (m *DNSHygieneCheckModule) isRFC1918(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	private := []string{"10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."}
	s := ip.String()
	for _, p := range private {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func (m *DNSHygieneCheckModule) calculateRisk(findings []map[string]interface{}) float64 {
	score := 0.0
	for _, f := range findings {
		switch strings.ToUpper(fmt.Sprint(f["severity"])) {
		case "HIGH":
			score += 25
		case "MEDIUM":
			score += 12
		case "INFO":
			score += 0
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

func (m *DNSHygieneCheckModule) summarize(findings []map[string]interface{}, servers int, zone string) string {
	high, med := 0, 0
	for _, f := range findings {
		switch strings.ToUpper(fmt.Sprint(f["severity"])) {
		case "HIGH":
			high++
		case "MEDIUM":
			med++
		}
	}
	z := zone
	if z == "" {
		z = "(no candidate zone)"
	}
	return fmt.Sprintf("Checked %d DNS server(s) with candidate zone %s; %d HIGH and %d MEDIUM issues detected.", servers, z, high, med)
}

func (m *DNSHygieneCheckModule) recommend(findings []map[string]interface{}) []string {
	reco := []string{
		"Restrict recursion to trusted subnets or disable it on authoritative-only servers.",
		"Disable zone transfers or restrict them to authorized secondaries using TSIG and IP allowlists.",
		"Ensure split-horizon DNS to prevent leakage of internal names externally.",
		"Enable detailed DNS logging and forward logs to SIEM for monitoring.",
	}
	return reco
}

// small utilities

func ioReadFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// Plugin constructor (Required)
func NewDNSHygieneCheckModulePlugin(logger *logger.Logger) modules.ModulePlugin {
	return NewDNSHygieneCheckModule(logger)
}

// Auto-registration (Required)
func init() {
	modules.RegisterPluginConstructor("WEAK_DNS_HYGIENE", NewDNSHygieneCheckModulePlugin)
}
