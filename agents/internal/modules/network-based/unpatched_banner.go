package networkbased

import (
	"bufio"
	"crypto/tls"
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// UnpatchedBannerDetectionModule inspects service banners/headers and flags old/EOL versions
type UnpatchedBannerDetectionModule struct {
	logger *logger.Logger
	info   modules.ModuleInfo
}

// NewUnpatchedBannerDetectionModule creates a new instance
func NewUnpatchedBannerDetectionModule(logger *logger.Logger) *UnpatchedBannerDetectionModule {
	return &UnpatchedBannerDetectionModule{
		logger: logger,
		info: modules.ModuleInfo{
			Name:             "Unpatched Service Banner Detection",
			Description:      "Grabs lightweight banners/headers and normalizes version strings (e.g., Apache 2.2.15, OpenSSH_7.2) to flag likely outdated or EOL software",
			CheckType:        "UNPATCHED_BANNER_DETECTION",
			Platform:         "windows",
			DefaultRiskLevel: "HIGH",
			RequiresAdmin:    false,
			Category:         modules.CategoryNetworkBased,
		},
	}
}

// GetInfo returns module info
func (m *UnpatchedBannerDetectionModule) GetInfo() modules.ModuleInfo { return m.info }

// Execute performs banner collection and simple age heuristics
func (m *UnpatchedBannerDetectionModule) Execute() (*modules.AssessmentResult, error) {
	m.logger.Info("Starting unpatched banner detection", nil)
	start := time.Now()

	targets, err := discoverLocalTargets(100, 24, 30) // cap hosts, /20..../30 safety
	if err != nil {
		return nil, fmt.Errorf("target discovery failed: %w", err)
	}

	// Common ports to probe (lightweight)
	type portProbe struct {
		port int
		tls  bool
		name string
	}
	probes := []portProbe{
		{21, false, "FTP"},
		{22, false, "SSH"},
		{25, false, "SMTP"},
		{80, false, "HTTP"},
		{110, false, "POP3"},
		{143, false, "IMAP"},
		{443, true, "HTTPS"},
		{3306, false, "MySQL"},
		{1433, false, "MSSQL"},
		{8080, false, "HTTP-Alt"},
		{8443, true, "HTTPS-Alt"},
		{5900, false, "VNC"},
	}

	findings := []map[string]interface{}{}
	for _, host := range targets {
		for _, p := range probes {
			b, hdrs := m.grabBanner(host, p.port, p.tls, 1200*time.Millisecond)
			if b == "" && len(hdrs) == 0 {
				continue
			}
			normalized := normalizeVersionStrings(b, hdrs)
			if len(normalized) == 0 {
				continue
			}

			// Simple heuristics: mark likely-old when under common thresholds (best-effort)
			heur := assessAgeHeuristics(normalized)
			if len(heur) == 0 {
				// Still record as info so backend can correlate against vuln databases
				findings = append(findings, map[string]interface{}{
					"host":        host,
					"port":        p.port,
					"service":     p.name,
					"severity":    "INFO",
					"issue":       "Service banner/version collected",
					"evidence":    normalized,
					"remediation": "Correlate versions with vulnerability database and apply patches as needed.",
					"timestamp":   time.Now(),
					"privacy":     "Only minimal banner text and normalized version tokens recorded.",
				})
				continue
			}

			// Produce one finding per flagged component
			for _, h := range heur {
				findings = append(findings, map[string]interface{}{
					"host":        host,
					"port":        p.port,
					"service":     p.name,
					"severity":    h.Severity,
					"issue":       fmt.Sprintf("Potentially outdated %s %s", h.Product, h.Version),
					"evidence":    normalized,
					"urgency":     h.Urgency,
					"remediation": "Update to a supported version; plan urgent patching for EOL or widely exploited versions.",
					"timestamp":   time.Now(),
					"privacy":     "Only minimal banner text and normalized version tokens recorded.",
				})
			}
		}
	}

	score := scoreBySeverity(findings, 20, 10, 0) // HIGH=20, MED=10
	level := modules.DetermineRiskLevel(score)

	result := &modules.AssessmentResult{
		CheckType: m.info.CheckType,
		RiskScore: score,
		RiskLevel: level,
		Data: map[string]interface{}{
			"summary":  summarizeSeverity(findings),
			"findings": findings,
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

// Validate checks basic network capability
func (m *UnpatchedBannerDetectionModule) Validate() error {
	_, err := net.Interfaces()
	return err
}

// ---------- helpers ----------

// grabBanner: safe, minimal probes. For TLS ports, do HTTPS HEAD /. For plain, read initial banner or send protocol hint.
func (m *UnpatchedBannerDetectionModule) grabBanner(host string, port int, useTLS bool, timeout time.Duration) (string, map[string]string) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	if useTLS {
		// HTTPS HEAD /
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
			ResponseHeaderTimeout: timeout,
			DisableKeepAlives:     true,
		}
		client := &http.Client{Transport: tr, Timeout: timeout}
		req, _ := http.NewRequest(http.MethodHead, "https://"+addr+"/", nil)
		resp, err := client.Do(req)
		if err != nil || resp == nil {
			return "", nil
		}
		defer resp.Body.Close()
		hdrs := map[string]string{}
		for k, v := range resp.Header {
			if len(v) > 0 {
				hdrs[strings.ToLower(k)] = v[0]
			}
		}
		// Build a concise banner-like string
		b := fmt.Sprintf("HTTP/%d.%d %d %s", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, strings.TrimSpace(resp.Status))
		if svr, ok := hdrs["server"]; ok {
			b = b + " | Server: " + svr
		}
		return b, hdrs
	}

	// Plain TCP: try to read banner first; if nothing, send minimal probe per-port
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))

	// Some services (SMTP/FTP/POP3/IMAP/SSH/VNC) send greeting lines
	reader := bufio.NewReader(c)
	c.SetWriteDeadline(time.Now().Add(timeout))

	// Port-based tiny nudges
	switch port {
	case 80, 8080:
		_, _ = c.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	case 25:
		// SMTP usually greets first; if not, send EHLO
		c.Write([]byte("EHLO example.com\r\n"))
	case 21:
		// FTP greets first; else send FEAT
		c.Write([]byte("FEAT\r\n"))
	case 110:
		c.Write([]byte("CAPA\r\n"))
	case 143:
		c.Write([]byte("a001 CAPABILITY\r\n"))
	case 3306:
		// MySQL sends handshake immediately
	case 1433:
		// MSSQL prelogin is binary; we won't send—just await banner if any
	case 5900:
		// VNC RFB greets immediately
	}
	// Read whatever is available quickly
	c.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, _ := reader.Read(buf)
	if n <= 0 {
		return "", nil
	}
	line := strings.TrimSpace(string(buf[:n]))
	hdrs := map[string]string{}
	// Parse HTTP headers if we accidentally hit an HTTP response
	if strings.HasPrefix(line, "HTTP/") {
		parts := strings.Split(line, "\r\n")
		for _, h := range parts {
			if i := strings.Index(h, ":"); i > 0 {
				k := strings.ToLower(strings.TrimSpace(h[:i]))
				v := strings.TrimSpace(h[i+1:])
				if k != "" && v != "" {
					hdrs[k] = v
				}
			}
		}
	}
	return line, hdrs
}

// normalizeVersionStrings pulls out "product name + version" tokens from banners/headers
func normalizeVersionStrings(banner string, headers map[string]string) []string {
	candidates := []string{}
	if banner != "" {
		candidates = append(candidates, banner)
	}
	for _, v := range headers {
		if v != "" {
			candidates = append(candidates, v)
		}
	}

	out := []string{}
	// Common regexes for product/version patterns
	pats := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(apache|nginx|httpd|iis)\s*/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`),
		regexp.MustCompile(`(?i)\b(openssh)[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`),
		regexp.MustCompile(`(?i)\b(vsftpd|proftpd|pure-ftpd)\s*/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`),
		regexp.MustCompile(`(?i)\b(dovecot|postfix|exim)\s*/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`),
		regexp.MustCompile(`(?i)\b(mysql|mariadb)\s*(?:server)?\s*/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`),
		regexp.MustCompile(`(?i)\b(microsoft[-\s]?iis)\s*/?\s*([0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)\b(rfb)\s*([0-9]+\.[0-9]+)`), // VNC
	}
	seen := map[string]struct{}{}
	for _, c := range candidates {
		for _, re := range pats {
			m := re.FindAllStringSubmatch(c, -1)
			for _, sub := range m {
				token := strings.TrimSpace(sub[1] + " " + sub[2])
				if token == "" {
					continue
				}
				if _, ok := seen[token]; !ok {
					seen[token] = struct{}{}
					out = append(out, token)
				}
			}
		}
	}
	return out
}

// simple age heuristics (best-effort): mark older major lines as MED/HIGH; backend can do CVE correlation
type ageHint struct {
	Product  string
	Version  string
	Severity string
	Urgency  string
}

func assessAgeHeuristics(tokens []string) []ageHint {
	out := []ageHint{}
	for _, t := range tokens {
		low := strings.ToLower(t)
		switch {
		case strings.Contains(low, "apache"):
			// Apache 2.2.* is EOL; early 2.4.* is old
			if strings.Contains(low, "2.2.") {
				out = append(out, ageHint{"Apache HTTPD", versionOnly(t), "HIGH", "Urgent (EOL)"})
			} else if strings.Contains(low, "2.4.1") || strings.Contains(low, "2.4.2") || strings.Contains(low, "2.4.3") {
				out = append(out, ageHint{"Apache HTTPD", versionOnly(t), "MEDIUM", "Plan Upgrade"})
			}
		case strings.Contains(low, "openssh"):
			// <8.0 often considered old in enterprise baselines
			if versionLessThan(versionOnly(t), "8.0") {
				out = append(out, ageHint{"OpenSSH", versionOnly(t), "MEDIUM", "Plan Upgrade"})
			}
		case strings.Contains(low, "nginx"):
			if versionLessThan(versionOnly(t), "1.18") { // LTS-ish baseline
				out = append(out, ageHint{"nginx", versionOnly(t), "MEDIUM", "Plan Upgrade"})
			}
		case strings.Contains(low, "mysql"):
			if versionLessThan(versionOnly(t), "5.7") {
				out = append(out, ageHint{"MySQL", versionOnly(t), "MEDIUM", "Plan Upgrade"})
			}
		case strings.Contains(low, "microsoft iis") || strings.Contains(low, "microsoft-iis"):
			if strings.Contains(low, "6.") || strings.Contains(low, "7.0") {
				out = append(out, ageHint{"Microsoft IIS", versionOnly(t), "HIGH", "Urgent (Old)"})
			}
		}
	}
	return out
}

func versionOnly(token string) string {
	fields := strings.Fields(token)
	if len(fields) == 0 {
		return token
	}
	return fields[len(fields)-1]
}

// simplistic semver-ish compare: "7.9" < "8.0"
func versionLessThan(a, b string) bool {
	ap := strings.SplitN(a, ".", 3)
	bp := strings.SplitN(b, ".", 3)
	for len(ap) < 3 {
		ap = append(ap, "0")
	}
	for len(bp) < 3 {
		bp = append(bp, "0")
	}
	for i := 0; i < 3; i++ {
		if ap[i] == bp[i] {
			continue
		}
		return num(ap[i]) < num(bp[i])
	}
	return false
}

func num(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// shared scoring/summaries used across modules
func scoreBySeverity(findings []map[string]interface{}, high, med, info int) float64 {
	score := 0.0
	for _, f := range findings {
		switch strings.ToUpper(fmt.Sprint(f["severity"])) {
		case "HIGH":
			score += float64(high)
		case "MEDIUM":
			score += float64(med)
		case "INFO":
			score += float64(info)
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

func summarizeSeverity(findings []map[string]interface{}) string {
	hi, me := 0, 0
	for _, f := range findings {
		switch strings.ToUpper(fmt.Sprint(f["severity"])) {
		case "HIGH":
			hi++
		case "MEDIUM":
			me++
		}
	}
	if len(findings) == 0 {
		return "No service banners were collected that indicate outdated software."
	}
	return fmt.Sprintf("Collected service versions with %d HIGH and %d MEDIUM potential patch findings.", hi, me)
}

// discoverLocalTargets enumerates local subnets and returns a capped host list
func discoverLocalTargets(maxHosts, minMask, maxMask int) ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	set := map[string]struct{}{}
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
			ones, _ := ipn.Mask.Size()
			if ones < minMask || ones > maxMask {
				continue
			}
			base := ipn.IP.Mask(ipn.Mask)
			// Walk a small slice of the subnet
			count := 0
			for h := IncIP(base); ipn.Contains(h) && count < 32; h = IncIP(h) {
				set[h.String()] = struct{}{}
				count++
			}
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
		if len(out) >= maxHosts {
			break
		}
	}
	return out, nil
}


// Plugin constructor (Required)
func NewUnpatchedBannerDetectionModulePlugin(logger *logger.Logger) modules.ModulePlugin {
	return NewUnpatchedBannerDetectionModule(logger)
}

// Auto-registration (Required)
func init() {
	modules.RegisterPluginConstructor("UNPATCHED_BANNER_DETECTION", NewUnpatchedBannerDetectionModulePlugin)
}
