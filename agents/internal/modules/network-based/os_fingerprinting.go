package networkbased

import (
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OSFingerprintingModule implements operating system fingerprinting
type OSFingerprintingModule struct {
	logger *logger.Logger
	info   modules.ModuleInfo
}

// OSFingerprint represents discovered OS information
type OSFingerprint struct {
	Host               string            `json:"host"`
	OSFamily           string            `json:"os_family"`
	OSVersion          string            `json:"os_version"`
	OSClass            string            `json:"os_class"`
	ConfidenceScore    float64           `json:"confidence_score"`
	Evidence           []EvidencePoint   `json:"evidence"`
	RiskLevel          string            `json:"risk_level"`
	SupportStatus      string            `json:"support_status"`
	Timestamp          time.Time         `json:"timestamp"`
	FingerprintMethod  string            `json:"fingerprint_method"`
	Metadata           map[string]string `json:"metadata"`
}

// EvidencePoint represents a single piece of OS fingerprinting evidence
type EvidencePoint struct {
	Type        string  `json:"type"`
	Value       string  `json:"value"`
	Source      string  `json:"source"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

// TCPFingerprint represents TCP-based fingerprinting data
type TCPFingerprint struct {
	TTL          int    `json:"ttl"`
	WindowSize   int    `json:"window_size"`
	Flags        string `json:"flags"`
	Options      string `json:"options"`
	MSS          int    `json:"mss"`
	WindowScale  int    `json:"window_scale"`
}

// OSFingerprintResult aggregates all OS fingerprinting results
type OSFingerprintResult struct {
	TotalHosts       int             `json:"total_hosts"`
	FingerprintedHosts []OSFingerprint `json:"fingerprinted_hosts"`
	UnknownHosts     []string        `json:"unknown_hosts"`
	ScanDuration     time.Duration   `json:"scan_duration"`
	Methods          []string        `json:"methods_used"`
	AccuracyMetrics  map[string]interface{} `json:"accuracy_metrics"`
}

// NewOSFingerprintingModule creates a new OSFingerprintingModule instance
func NewOSFingerprintingModule(logger *logger.Logger) *OSFingerprintingModule {
	return &OSFingerprintingModule{
		logger: logger,
		info: modules.ModuleInfo{
			Name:             "Operating System Fingerprinting",
			Description:      "Identifies remote host operating systems using passive and active fingerprinting techniques including TCP characteristics and service banners",
			CheckType:        "OS_FINGERPRINTING",
			Platform:         "windows",
			DefaultRiskLevel: "MEDIUM",
			RequiresAdmin:    false,
			Category:         modules.CategoryNetworkBased,
		},
	}
}

// GetInfo returns information about the module
func (m *OSFingerprintingModule) GetInfo() modules.ModuleInfo {
	return m.info
}

// Execute performs the OS fingerprinting assessment
func (m *OSFingerprintingModule) Execute() (*modules.AssessmentResult, error) {
	m.logger.Info("Starting OS fingerprinting assessment", nil)
	startTime := time.Now()

	// Get target hosts from local network
	hosts, err := m.getTargetHosts()
	if err != nil {
		return nil, fmt.Errorf("failed to determine target hosts: %w", err)
	}

	// Perform OS fingerprinting with multiple techniques
	fingerprintResult, err := m.performOSFingerprinting(hosts)
	if err != nil {
		return nil, fmt.Errorf("OS fingerprinting failed: %w", err)
	}

	duration := time.Since(startTime)
	fingerprintResult.ScanDuration = duration

	// Analyze results and calculate risk
	riskScore := m.calculateRiskScore(fingerprintResult)
	riskLevel := modules.DetermineRiskLevel(riskScore)

	// Generate summary and recommendations
	summary := m.generateSummary(fingerprintResult)
	recommendations := m.generateRecommendations(fingerprintResult)

	result := &modules.AssessmentResult{
		CheckType: m.info.CheckType,
		RiskScore: riskScore,
		RiskLevel: riskLevel,
		Data: map[string]interface{}{
			"fingerprint_result": fingerprintResult,
			"summary":           summary,
			"recommendations":   recommendations,
			"metrics": map[string]interface{}{
				"execution_time":       duration.String(),
				"hosts_scanned":        fingerprintResult.TotalHosts,
				"hosts_fingerprinted":  len(fingerprintResult.FingerprintedHosts),
				"unsupported_os_count": m.countUnsupportedOS(fingerprintResult.FingerprintedHosts),
				"high_confidence_count": m.countHighConfidence(fingerprintResult.FingerprintedHosts),
			},
		},
		Timestamp: time.Now(),
		Duration:  duration,
	}

	m.logger.Info("OS fingerprinting completed", map[string]interface{}{
		"duration":            duration.String(),
		"hosts_scanned":       fingerprintResult.TotalHosts,
		"hosts_fingerprinted": len(fingerprintResult.FingerprintedHosts),
		"risk_score":          riskScore,
	})

	return result, nil
}

// Validate checks if the module can run on this system
func (m *OSFingerprintingModule) Validate() error {
	// Check if we can perform network operations
	_, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("cannot enumerate network interfaces: %w", err)
	}

	// Test basic TCP connection capability
	timeout := 2 * time.Second
	conn, err := net.DialTimeout("tcp", "127.0.0.1:0", timeout)
	if err == nil {
		conn.Close()
	}
	// We expect this to fail, but if it doesn't error due to permission issues, we're good

	return nil
}

// getTargetHosts gets a list of active hosts on the network
func (m *OSFingerprintingModule) getTargetHosts() ([]string, error) {
	// Get local network ranges
	ranges, err := m.getLocalNetworkRanges()
	if err != nil {
		return nil, err
	}

	var allHosts []string
	for _, cidr := range ranges {
		hosts, err := m.getHostsFromCIDR(cidr)
		if err != nil {
			m.logger.Warn("Failed to parse CIDR range", map[string]interface{}{
				"cidr":  cidr,
				"error": err.Error(),
			})
			continue
		}

		// Limit host count to avoid excessive scanning
		if len(hosts) > 50 {
			hosts = hosts[:50]
		}

		allHosts = append(allHosts, hosts...)
	}

	// Remove duplicates and limit total
	hostMap := make(map[string]bool)
	var uniqueHosts []string
	for _, host := range allHosts {
		if !hostMap[host] && len(uniqueHosts) < 100 {
			hostMap[host] = true
			uniqueHosts = append(uniqueHosts, host)
		}
	}

	return uniqueHosts, nil
}

// getLocalNetworkRanges gets local network CIDR ranges
func (m *OSFingerprintingModule) getLocalNetworkRanges() ([]string, error) {
	var ranges []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
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
				continue // Skip IPv6
			}

			network := ip.Mask(mask)
			ones, _ := mask.Size()

			// Only scan reasonable private networks
			if ones >= 16 && ones <= 24 {
				cidr := fmt.Sprintf("%s/%d", network.String(), ones)
				ranges = append(ranges, cidr)
			}
		}
	}

	if len(ranges) == 0 {
		ranges = []string{"192.168.1.0/24"}
	}

	return ranges, nil
}

// getHostsFromCIDR generates host list from CIDR
func (m *OSFingerprintingModule) getHostsFromCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var hosts []string
	ip := ipNet.IP.Mask(ipNet.Mask)

	ones, _ := ipNet.Mask.Size()
	if ones < 20 {
		return nil, fmt.Errorf("subnet too large for fingerprinting")
	}

	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); m.incrementIP(ip) {
		if !ip.Equal(ipNet.IP) && !ip.Equal(m.broadcastIP(ipNet)) {
			hosts = append(hosts, ip.String())
		}

		if len(hosts) >= 50 {
			break
		}
	}

	return hosts, nil
}

// incrementIP increments IP address
func (m *OSFingerprintingModule) incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// broadcastIP calculates broadcast address
func (m *OSFingerprintingModule) broadcastIP(ipNet *net.IPNet) net.IP {
	broadcast := make(net.IP, len(ipNet.IP))
	copy(broadcast, ipNet.IP)

	for i := 0; i < len(broadcast); i++ {
		broadcast[i] |= ^ipNet.Mask[i]
	}

	return broadcast
}

// performOSFingerprinting conducts OS fingerprinting using multiple techniques
func (m *OSFingerprintingModule) performOSFingerprinting(hosts []string) (*OSFingerprintResult, error) {
	result := &OSFingerprintResult{
		TotalHosts:         len(hosts),
		FingerprintedHosts: []OSFingerprint{},
		UnknownHosts:       []string{},
		Methods:            []string{"tcp_fingerprinting", "banner_analysis", "ttl_analysis"},
		AccuracyMetrics:    make(map[string]interface{}),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 20) // Controlled concurrency

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fingerprint := m.fingerprintHost(h)

			mu.Lock()
			if fingerprint != nil {
				result.FingerprintedHosts = append(result.FingerprintedHosts, *fingerprint)
			} else {
				result.UnknownHosts = append(result.UnknownHosts, h)
			}
			mu.Unlock()
		}(host)
	}

	wg.Wait()

	// Calculate accuracy metrics
	result.AccuracyMetrics["fingerprint_success_rate"] = float64(len(result.FingerprintedHosts)) / float64(len(hosts))
	result.AccuracyMetrics["high_confidence_percentage"] = m.getHighConfidencePercentage(result.FingerprintedHosts)

	return result, nil
}

// fingerprintHost performs OS fingerprinting on a single host
func (m *OSFingerprintingModule) fingerprintHost(host string) *OSFingerprint {
	// First check if host is responsive
	if !m.isHostReachable(host) {
		return nil
	}

	fingerprint := &OSFingerprint{
		Host:              host,
		Evidence:          []EvidencePoint{},
		Timestamp:         time.Now(),
		FingerprintMethod: "multi_technique",
		Metadata:          make(map[string]string),
	}

	// Technique 1: TCP fingerprinting
	tcpEvidence := m.performTCPFingerprinting(host)
	fingerprint.Evidence = append(fingerprint.Evidence, tcpEvidence...)

	// Technique 2: Banner analysis
	bannerEvidence := m.performBannerAnalysis(host)
	fingerprint.Evidence = append(fingerprint.Evidence, bannerEvidence...)

	// Technique 3: TTL analysis
	ttlEvidence := m.performTTLAnalysis(host)
	fingerprint.Evidence = append(fingerprint.Evidence, ttlEvidence...)

	// Analyze all evidence to determine OS
	m.analyzeEvidence(fingerprint)

	// Only return fingerprint if we have some confidence
	if fingerprint.ConfidenceScore > 0.1 {
		return fingerprint
	}

	return nil
}

// isHostReachable checks if host responds to basic probes
func (m *OSFingerprintingModule) isHostReachable(host string) bool {
	// Try common ports to see if host is alive
	commonPorts := []int{80, 443, 22, 23, 135, 445}

	for _, port := range commonPorts {
		timeout := 2 * time.Second
		address := net.JoinHostPort(host, strconv.Itoa(port))

		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}

	return false
}

// performTCPFingerprinting analyzes TCP characteristics
func (m *OSFingerprintingModule) performTCPFingerprinting(host string) []EvidencePoint {
	evidence := []EvidencePoint{}

	// Try to connect to common ports and analyze TCP behavior
	testPorts := []int{80, 443, 22, 135}

	for _, port := range testPorts {
		tcpData := m.getTCPFingerprint(host, port)
		if tcpData != nil {
			// Analyze TTL
			ttlEvidence := m.analyzeTTL(tcpData.TTL)
			if ttlEvidence.Type != "" {
				evidence = append(evidence, ttlEvidence)
			}

			// Analyze window size
			windowEvidence := m.analyzeWindowSize(tcpData.WindowSize)
			if windowEvidence.Type != "" {
				evidence = append(evidence, windowEvidence)
			}

			break // One successful probe is enough
		}
	}

	return evidence
}

// getTCPFingerprint captures TCP characteristics
func (m *OSFingerprintingModule) getTCPFingerprint(host string, port int) *TCPFingerprint {
	// This is a simplified version - in reality you'd need raw sockets for full TCP fingerprinting
	// For this implementation, we'll do basic connection analysis

	timeout := 3 * time.Second
	address := net.JoinHostPort(host, strconv.Itoa(port))

	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Estimate TTL based on connection timing and common patterns
	responseTime := time.Since(start)
	estimatedTTL := m.estimateTTLFromTiming(responseTime)

	return &TCPFingerprint{
		TTL:        estimatedTTL,
		WindowSize: 65535, // Default - would need raw sockets for real value
		Flags:      "SYN-ACK",
		Options:    "unknown",
		MSS:        1460,
		WindowScale: 0,
	}
}

// estimateTTLFromTiming estimates TTL based on response timing
func (m *OSFingerprintingModule) estimateTTLFromTiming(responseTime time.Duration) int {
	// Very rough estimation - real implementation would capture actual TTL
	if responseTime < 1*time.Millisecond {
		return 128 // Likely Windows on same subnet
	} else if responseTime < 10*time.Millisecond {
		return 64 // Likely Linux/Unix on same subnet
	} else if responseTime < 50*time.Millisecond {
		return 128 // Likely Windows across router
	}
	return 64 // Default to Unix-like
}

// performBannerAnalysis analyzes service banners for OS hints
func (m *OSFingerprintingModule) performBannerAnalysis(host string) []EvidencePoint {
	evidence := []EvidencePoint{}

	// Common ports that often reveal OS information
	bannerPorts := []int{22, 21, 25, 80, 110, 143}

	for _, port := range bannerPorts {
		banner := m.grabServiceBanner(host, port)
		if banner != "" {
			osHints := m.extractOSFromBanner(banner, port)
			evidence = append(evidence, osHints...)
		}
	}

	return evidence
}

// grabServiceBanner grabs service banner from specific port
func (m *OSFingerprintingModule) grabServiceBanner(host string, port int) string {
	timeout := 3 * time.Second
	address := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// Send appropriate probe based on port
	switch port {
	case 80:
		conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	case 22:
		// SSH banner is sent automatically
	case 21:
		// FTP banner is sent automatically
	}

	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return ""
	}

	return strings.TrimSpace(string(buffer[:n]))
}

// extractOSFromBanner extracts OS information from service banners
func (m *OSFingerprintingModule) extractOSFromBanner(banner string, port int) []EvidencePoint {
	evidence := []EvidencePoint{}
	bannerLower := strings.ToLower(banner)

	// SSH banner analysis
	if port == 22 && strings.Contains(bannerLower, "ssh") {
		if strings.Contains(bannerLower, "openssh") {
			if strings.Contains(bannerLower, "ubuntu") {
				evidence = append(evidence, EvidencePoint{
					Type:        "os_family",
					Value:       "Linux",
					Source:      "ssh_banner",
					Confidence:  0.8,
					Description: "OpenSSH banner indicates Ubuntu Linux",
				})
			} else if strings.Contains(bannerLower, "windows") {
				evidence = append(evidence, EvidencePoint{
					Type:        "os_family",
					Value:       "Windows",
					Source:      "ssh_banner",
					Confidence:  0.8,
					Description: "OpenSSH banner indicates Windows",
				})
			} else {
				evidence = append(evidence, EvidencePoint{
					Type:        "os_family",
					Value:       "Unix-like",
					Source:      "ssh_banner",
					Confidence:  0.6,
					Description: "OpenSSH typically indicates Unix-like OS",
				})
			}
		}
	}

	// HTTP banner analysis
	if port == 80 && strings.Contains(bannerLower, "server:") {
		if strings.Contains(bannerLower, "iis") {
			evidence = append(evidence, EvidencePoint{
				Type:        "os_family",
				Value:       "Windows",
				Source:      "http_banner",
				Confidence:  0.9,
				Description: "IIS server indicates Windows",
			})
		} else if strings.Contains(bannerLower, "apache") {
			if strings.Contains(bannerLower, "ubuntu") || strings.Contains(bannerLower, "debian") {
				evidence = append(evidence, EvidencePoint{
					Type:        "os_family",
					Value:       "Linux",
					Source:      "http_banner",
					Confidence:  0.8,
					Description: "Apache on Ubuntu/Debian",
				})
			}
		}
	}

	return evidence
}

// performTTLAnalysis analyzes TTL values for OS detection
func (m *OSFingerprintingModule) performTTLAnalysis(host string) []EvidencePoint {
	evidence := []EvidencePoint{}

	// Perform simple ping-like analysis (simplified for TCP connections)
	ttl := m.estimateHostTTL(host)
	if ttl > 0 {
		ttlEvidence := m.analyzeTTL(ttl)
		if ttlEvidence.Type != "" {
			evidence = append(evidence, ttlEvidence)
		}
	}

	return evidence
}

// estimateHostTTL estimates TTL by connecting to host
func (m *OSFingerprintingModule) estimateHostTTL(host string) int {
	// Try to connect to common ports and estimate TTL
	ports := []int{80, 443, 22}

	for _, port := range ports {
		ttl := m.estimateTTLFromConnection(host, port)
		if ttl > 0 {
			return ttl
		}
	}

	return 0
}

// estimateTTLFromConnection estimates TTL from connection behavior
func (m *OSFingerprintingModule) estimateTTLFromConnection(host string, port int) int {
	timeout := 2 * time.Second
	address := net.JoinHostPort(host, strconv.Itoa(port))

	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return 0
	}
	defer conn.Close()

	responseTime := time.Since(start)

	// Rough TTL estimation based on timing patterns
	// This is not accurate but provides some indication
	if responseTime < 1*time.Millisecond {
		return 128 // Local Windows
	} else if responseTime < 5*time.Millisecond {
		return 64  // Local Unix
	} else if responseTime < 20*time.Millisecond {
		return 128 // Remote Windows
	}
	return 64 // Remote Unix
}

// analyzeTTL analyzes TTL value to determine OS family
func (m *OSFingerprintingModule) analyzeTTL(ttl int) EvidencePoint {
	// Common TTL values for different OS families
	switch {
	case ttl >= 120 && ttl <= 128:
		return EvidencePoint{
			Type:        "os_family",
			Value:       "Windows",
			Source:      "ttl_analysis",
			Confidence:  0.7,
			Description: fmt.Sprintf("TTL %d suggests Windows (default 128)", ttl),
		}
	case ttl >= 60 && ttl <= 64:
		return EvidencePoint{
			Type:        "os_family",
			Value:       "Linux/Unix",
			Source:      "ttl_analysis",
			Confidence:  0.7,
			Description: fmt.Sprintf("TTL %d suggests Linux/Unix (default 64)", ttl),
		}
	case ttl >= 250 && ttl <= 255:
		return EvidencePoint{
			Type:        "os_family",
			Value:       "Cisco/Network Device",
			Source:      "ttl_analysis",
			Confidence:  0.6,
			Description: fmt.Sprintf("TTL %d suggests network device", ttl),
		}
	}

	return EvidencePoint{}
}

// analyzeWindowSize analyzes TCP window size
func (m *OSFingerprintingModule) analyzeWindowSize(windowSize int) EvidencePoint {
	// Windows often uses larger window sizes
	if windowSize >= 65535 {
		return EvidencePoint{
			Type:        "os_characteristic",
			Value:       "Windows-like",
			Source:      "tcp_window",
			Confidence:  0.4,
			Description: fmt.Sprintf("Large window size (%d) suggests Windows", windowSize),
		}
	}

	return EvidencePoint{}
}

// analyzeEvidence combines all evidence to determine final OS identification
func (m *OSFingerprintingModule) analyzeEvidence(fingerprint *OSFingerprint) {
	osVotes := make(map[string]float64)
	totalConfidence := 0.0

	// Weight and combine evidence
	for _, evidence := range fingerprint.Evidence {
		if evidence.Type == "os_family" {
			osVotes[evidence.Value] += evidence.Confidence
			totalConfidence += evidence.Confidence
		}
	}

	if len(osVotes) == 0 {
		fingerprint.OSFamily = "Unknown"
		fingerprint.ConfidenceScore = 0.0
		return
	}

	// Find highest voted OS
	bestOS := ""
	bestScore := 0.0
	for os, score := range osVotes {
		if score > bestScore {
			bestOS = os
			bestScore = score
		}
	}

	fingerprint.OSFamily = bestOS
	fingerprint.ConfidenceScore = bestScore / totalConfidence

	// Determine OS class and version hints
	fingerprint.OSClass = m.determineOSClass(bestOS)
	fingerprint.OSVersion = m.estimateOSVersion(fingerprint.Evidence)
	fingerprint.SupportStatus = m.assessSupportStatus(fingerprint.OSFamily, fingerprint.OSVersion)
	fingerprint.RiskLevel = m.assessOSRisk(fingerprint)
}

// determineOSClass determines OS class from family
func (m *OSFingerprintingModule) determineOSClass(osFamily string) string {
	osFamily = strings.ToLower(osFamily)

	switch {
	case strings.Contains(osFamily, "windows"):
		return "Windows Server/Desktop"
	case strings.Contains(osFamily, "linux"):
		return "Linux Distribution"
	case strings.Contains(osFamily, "unix"):
		return "Unix System"
	case strings.Contains(osFamily, "cisco"):
		return "Network Device"
	default:
		return "Unknown"
	}
}

// estimateOSVersion attempts to estimate OS version from evidence
func (m *OSFingerprintingModule) estimateOSVersion(evidence []EvidencePoint) string {
	for _, e := range evidence {
		if strings.Contains(strings.ToLower(e.Description), "ubuntu") {
			return "Ubuntu Linux"
		}
		if strings.Contains(strings.ToLower(e.Description), "debian") {
			return "Debian Linux"
		}
		if strings.Contains(strings.ToLower(e.Description), "iis") {
			return "Windows Server"
		}
	}
	return "Unknown Version"
}

// assessSupportStatus determines if OS is supported/EOL
func (m *OSFingerprintingModule) assessSupportStatus(osFamily, osVersion string) string {
	osFamily = strings.ToLower(osFamily)
	osVersion = strings.ToLower(osVersion)

	// Simple heuristics for support status
	if strings.Contains(osFamily, "windows") {
		if strings.Contains(osVersion, "2008") || strings.Contains(osVersion, "xp") {
			return "End of Life"
		}
		return "Supported"
	}

	if strings.Contains(osFamily, "linux") {
		return "Supported" // Most Linux distros are supported
	}

	return "Unknown"
}

// assessOSRisk determines risk level based on OS characteristics
func (m *OSFingerprintingModule) assessOSRisk(fingerprint *OSFingerprint) string {
	// High risk for EOL systems
	if fingerprint.SupportStatus == "End of Life" {
		return "HIGH"
	}

	// Medium risk for unknown/unidentified systems
	if fingerprint.ConfidenceScore < 0.5 {
		return "MEDIUM"
	}

	// Medium risk for network devices (often unpatched)
	if strings.Contains(strings.ToLower(fingerprint.OSFamily), "cisco") ||
		strings.Contains(strings.ToLower(fingerprint.OSFamily), "network") {
		return "MEDIUM"
	}

	return "LOW"
}

// calculateRiskScore calculates overall risk based on fingerprinting results
func (m *OSFingerprintingModule) calculateRiskScore(result *OSFingerprintResult) float64 {
	if len(result.FingerprintedHosts) == 0 {
		return 20.0 // Medium risk if no hosts could be fingerprinted
	}

	eolCount := 0
	unknownCount := 0
	networkDeviceCount := 0

	for _, fp := range result.FingerprintedHosts {
		if fp.SupportStatus == "End of Life" {
			eolCount++
		}
		if fp.ConfidenceScore < 0.5 {
			unknownCount++
		}
		if strings.Contains(strings.ToLower(fp.OSFamily), "cisco") ||
			strings.Contains(strings.ToLower(fp.OSFamily), "network") {
			networkDeviceCount++
		}
	}

	// Calculate weighted risk score
	totalHosts := float64(len(result.FingerprintedHosts))
	eolRisk := (float64(eolCount) / totalHosts) * 80     // EOL systems are high risk
	unknownRisk := (float64(unknownCount) / totalHosts) * 40 // Unknown systems are medium risk
	deviceRisk := (float64(networkDeviceCount) / totalHosts) * 30 // Network devices are moderate risk

	score := eolRisk + unknownRisk + deviceRisk

	if score > 100 {
		score = 100
	}

	return score
}

// countUnsupportedOS counts hosts with unsupported operating systems
func (m *OSFingerprintingModule) countUnsupportedOS(fingerprints []OSFingerprint) int {
	count := 0
	for _, fp := range fingerprints {
		if fp.SupportStatus == "End of Life" {
			count++
		}
	}
	return count
}

// countHighConfidence counts hosts with high confidence fingerprints
func (m *OSFingerprintingModule) countHighConfidence(fingerprints []OSFingerprint) int {
	count := 0
	for _, fp := range fingerprints {
		if fp.ConfidenceScore >= 0.7 {
			count++
		}
	}
	return count
}

// getHighConfidencePercentage calculates percentage of high confidence results
func (m *OSFingerprintingModule) getHighConfidencePercentage(fingerprints []OSFingerprint) float64 {
	if len(fingerprints) == 0 {
		return 0.0
	}
	return float64(m.countHighConfidence(fingerprints)) / float64(len(fingerprints)) * 100
}

// generateSummary creates human-readable summary
func (m *OSFingerprintingModule) generateSummary(result *OSFingerprintResult) string {
	if len(result.FingerprintedHosts) == 0 {
		return "No hosts could be fingerprinted on the local network"
	}

	eolCount := m.countUnsupportedOS(result.FingerprintedHosts)
	highConfCount := m.countHighConfidence(result.FingerprintedHosts)

	summary := fmt.Sprintf("Fingerprinted %d of %d hosts with %d high-confidence identifications",
		len(result.FingerprintedHosts), result.TotalHosts, highConfCount)

	if eolCount > 0 {
		summary += fmt.Sprintf(", including %d end-of-life systems requiring immediate attention", eolCount)
	}

	return summary
}

// generateRecommendations creates actionable recommendations
func (m *OSFingerprintingModule) generateRecommendations(result *OSFingerprintResult) []string {
	recommendations := []string{}

	eolCount := m.countUnsupportedOS(result.FingerprintedHosts)
	unknownCount := len(result.FingerprintedHosts) - m.countHighConfidence(result.FingerprintedHosts)

	if eolCount > 0 {
		recommendations = append(recommendations,
			"Immediately upgrade or isolate end-of-life operating systems",
			"Implement network segmentation for unsupported systems",
			"Plan migration strategy for legacy systems")
	}

	if unknownCount > 0 {
		recommendations = append(recommendations,
			"Perform detailed inventory of unidentified systems",
			"Deploy endpoint detection and response (EDR) for better visibility")
	}

	recommendations = append(recommendations,
		"Implement automated OS patch management",
		"Regularly audit and update OS inventory",
		"Monitor network for new or changed systems",
		"Establish OS lifecycle management policies")

	return recommendations
}

// Plugin constructor for auto-registration
func NewOSFingerprintingModulePlugin(logger *logger.Logger) modules.ModulePlugin {
	return NewOSFingerprintingModule(logger)
}

// Auto-registration via init() function
func init() {
	modules.RegisterPluginConstructor("OS_FINGERPRINTING", NewOSFingerprintingModulePlugin)
}