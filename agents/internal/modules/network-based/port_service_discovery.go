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

// PortServiceDiscoveryModule implements network port and service discovery
type PortServiceDiscoveryModule struct {
	logger *logger.Logger
	info   modules.ModuleInfo
	modules.TargetAware
}

// ServiceFingerprint represents discovered service information
type ServiceFingerprint struct {
	Port        int               `json:"port"`
	Protocol    string            `json:"protocol"`
	Service     string            `json:"service"`
	Banner      string            `json:"banner"`
	Version     string            `json:"version"`
	Host        string            `json:"host"`
	Status      string            `json:"status"`
	Metadata    map[string]string `json:"metadata"`
	RiskLevel   string            `json:"risk_level"`
	Timestamp   time.Time         `json:"timestamp"`
}

// ScanResult aggregates all discovery results
type ScanResult struct {
	TotalHosts    int                  `json:"total_hosts"`
	TotalPorts    int                  `json:"total_ports"`
	ActiveHosts   []string             `json:"active_hosts"`
	Services      []ServiceFingerprint `json:"services"`
	ScanDuration  time.Duration        `json:"scan_duration"`
	ConcurrencyLevel int               `json:"concurrency_level"`
	TimeoutUsed   time.Duration        `json:"timeout_used"`
}

// NewPortServiceDiscoveryModule creates a new PortServiceDiscoveryModule instance
func NewPortServiceDiscoveryModule(logger *logger.Logger) *PortServiceDiscoveryModule {
	return &PortServiceDiscoveryModule{
		logger: logger,
		info: modules.ModuleInfo{
			Name:             "Port & Service Discovery",
			Description:      "Discovers open TCP and UDP ports on local network hosts with basic service identification and banner grabbing",
			CheckType:        "PORT_SERVICE_DISCOVERY",
			Platform:         "windows",
			DefaultRiskLevel: "MEDIUM",
			RequiresAdmin:    false,
			Category:         modules.CategoryNetworkBased,
		},
	}
}

// GetInfo returns information about the module
func (m *PortServiceDiscoveryModule) GetInfo() modules.ModuleInfo {
	return m.info
}

// Execute performs the port and service discovery assessment
func (m *PortServiceDiscoveryModule) Execute() (*modules.AssessmentResult, error) {
	m.logger.Info("Starting port and service discovery assessment", nil)
	startTime := time.Now()

	// Get network ranges - use target context if available, otherwise auto-discover
	var networkRanges []string
	var err error

	target := m.Target()
	if target.IP != "" {
		// Use specific target IP from job context
		networkRanges = []string{target.IP}
		m.logger.Debug("Using target IP from context", map[string]interface{}{"target": target.IP})
	} else {
		// Fall back to auto-discovery for backward compatibility
		networkRanges, err = m.getLocalNetworkRanges()
		if err != nil {
			return nil, fmt.Errorf("failed to determine local network ranges: %w", err)
		}
		m.logger.Debug("Auto-discovered network ranges", map[string]interface{}{"count": len(networkRanges)})
	}

	// Define Tier-A port lists from specifications
	tcpPorts := []int{22, 23, 80, 88, 110, 135, 137, 138, 139, 143, 161, 389, 443, 445, 3389, 3306, 1433, 1521, 2049, 27017, 5900, 8080, 8443}
	udpPorts := []int{53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900, 5353, 5355}

	// Perform discovery with controlled concurrency
	scanResult, err := m.performDiscovery(networkRanges, tcpPorts, udpPorts)
	if err != nil {
		return nil, fmt.Errorf("discovery failed: %w", err)
	}

	duration := time.Since(startTime)
	scanResult.ScanDuration = duration

	// Analyze results and calculate risk
	riskScore := m.calculateRiskScore(scanResult)
	riskLevel := modules.DetermineRiskLevel(riskScore)

	// Generate summary and recommendations
	summary := m.generateSummary(scanResult)
	recommendations := m.generateRecommendations(scanResult)

	result := &modules.AssessmentResult{
		CheckType: m.info.CheckType,
		RiskScore: riskScore,
		RiskLevel: riskLevel,
		Data: map[string]interface{}{
			"scan_result":     scanResult,
			"summary":         summary,
			"recommendations": recommendations,
			"metrics": map[string]interface{}{
				"execution_time":     duration.String(),
				"hosts_scanned":      scanResult.TotalHosts,
				"services_found":     len(scanResult.Services),
				"high_risk_services": m.countHighRiskServices(scanResult.Services),
			},
		},
		Timestamp: time.Now(),
		Duration:  duration,
	}

	m.logger.Info("Port and service discovery completed", map[string]interface{}{
		"duration":        duration.String(),
		"hosts_scanned":   scanResult.TotalHosts,
		"services_found":  len(scanResult.Services),
		"risk_score":      riskScore,
	})

	return result, nil
}

// Validate checks if the module can run on this system
func (m *PortServiceDiscoveryModule) Validate() error {
	// Check if we can resolve local network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("cannot enumerate network interfaces: %w", err)
	}

	activeCount := 0
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			activeCount++
		}
	}

	if activeCount == 0 {
		return fmt.Errorf("no active network interfaces found")
	}

	return nil
}

// getLocalNetworkRanges determines the local network ranges to scan
func (m *PortServiceDiscoveryModule) getLocalNetworkRanges() ([]string, error) {
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
				continue // Skip IPv6 for now
			}

			// Calculate network address
			network := ip.Mask(mask)
			ones, _ := mask.Size()

			// Only scan smaller networks (avoid scanning internet)
			if ones >= 16 && ones <= 24 {
				cidr := fmt.Sprintf("%s/%d", network.String(), ones)
				ranges = append(ranges, cidr)
			}
		}
	}

	if len(ranges) == 0 {
		// Fallback to common private ranges
		ranges = []string{"192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24"}
	}

	return ranges, nil
}

// performDiscovery conducts the actual port scanning
func (m *PortServiceDiscoveryModule) performDiscovery(networkRanges []string, tcpPorts, udpPorts []int) (*ScanResult, error) {
	result := &ScanResult{
		Services:         []ServiceFingerprint{},
		ActiveHosts:      []string{},
		ConcurrencyLevel: 50, // Controlled concurrency
		TimeoutUsed:      3 * time.Second,
	}

	var allServices []ServiceFingerprint
	var allHosts []string
	var mu sync.Mutex

	// Worker pool for controlled concurrency
	semaphore := make(chan struct{}, result.ConcurrencyLevel)
	var wg sync.WaitGroup

	for _, networkRange := range networkRanges {
		hosts, err := m.getHostsFromCIDR(networkRange)
		if err != nil {
			m.logger.Warn("Failed to parse network range", map[string]interface{}{
				"range": networkRange,
				"error": err.Error(),
			})
			continue
		}

		result.TotalHosts += len(hosts)

		for _, host := range hosts {
			// TCP port scanning
			for _, port := range tcpPorts {
				wg.Add(1)
				go func(h string, p int) {
					defer wg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					if service := m.scanTCPPort(h, p); service != nil {
						mu.Lock()
						allServices = append(allServices, *service)
						// Add host to active list if not already present
						hostFound := false
						for _, activeHost := range allHosts {
							if activeHost == h {
								hostFound = true
								break
							}
						}
						if !hostFound {
							allHosts = append(allHosts, h)
						}
						mu.Unlock()
					}
				}(host, port)
			}

			// UDP port scanning (more limited)
			for _, port := range udpPorts {
				wg.Add(1)
				go func(h string, p int) {
					defer wg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					if service := m.scanUDPPort(h, p); service != nil {
						mu.Lock()
						allServices = append(allServices, *service)
						// Add host to active list if not already present
						hostFound := false
						for _, activeHost := range allHosts {
							if activeHost == h {
								hostFound = true
								break
							}
						}
						if !hostFound {
							allHosts = append(allHosts, h)
						}
						mu.Unlock()
					}
				}(host, port)
			}
		}
	}

	wg.Wait()

	result.Services = allServices
	result.ActiveHosts = allHosts
	result.TotalPorts = len(tcpPorts) + len(udpPorts)

	return result, nil
}

// getHostsFromCIDR generates list of hosts from CIDR notation
func (m *PortServiceDiscoveryModule) getHostsFromCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var hosts []string
	ip := ipNet.IP.Mask(ipNet.Mask)

	// Limit to reasonable subnet sizes to avoid scanning entire internet
	ones, _ := ipNet.Mask.Size()
	if ones < 16 {
		return nil, fmt.Errorf("subnet too large, maximum /16 supported")
	}

	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); m.incrementIP(ip) {
		// Skip network and broadcast addresses
		if !ip.Equal(ipNet.IP) && !ip.Equal(m.broadcastIP(ipNet)) {
			hosts = append(hosts, ip.String())
		}

		// Safety limit - don't scan more than 254 hosts per range
		if len(hosts) >= 254 {
			break
		}
	}

	return hosts, nil
}

// incrementIP increments an IP address
func (m *PortServiceDiscoveryModule) incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// broadcastIP calculates broadcast address for a network
func (m *PortServiceDiscoveryModule) broadcastIP(ipNet *net.IPNet) net.IP {
	broadcast := make(net.IP, len(ipNet.IP))
	copy(broadcast, ipNet.IP)

	for i := 0; i < len(broadcast); i++ {
		broadcast[i] |= ^ipNet.Mask[i]
	}

	return broadcast
}

// scanTCPPort scans a specific TCP port and attempts banner grabbing
func (m *PortServiceDiscoveryModule) scanTCPPort(host string, port int) *ServiceFingerprint {
	timeout := 3 * time.Second
	address := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil // Port closed or unreachable
	}
	defer conn.Close()

	service := &ServiceFingerprint{
		Host:      host,
		Port:      port,
		Protocol:  "tcp",
		Status:    "open",
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
	}

	// Attempt banner grabbing with protocol-specific probes
	banner := m.grabTCPBanner(conn, port)
	if banner != "" {
		service.Banner = banner
		service.Service, service.Version = m.identifyService(port, banner)
	} else {
		service.Service = m.getCommonServiceName(port, "tcp")
	}

	// Assess risk level
	service.RiskLevel = m.assessServiceRisk(service)

	return service
}

// scanUDPPort scans a specific UDP port with targeted queries
func (m *PortServiceDiscoveryModule) scanUDPPort(host string, port int) *ServiceFingerprint {
	timeout := 2 * time.Second
	address := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Send protocol-specific UDP probe
	probe := m.getUDPProbe(port)
	if probe == nil {
		return nil // No probe available for this port
	}

	conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write(probe)
	if err != nil {
		return nil
	}

	// Try to read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil // No response or error
	}

	service := &ServiceFingerprint{
		Host:      host,
		Port:      port,
		Protocol:  "udp",
		Status:    "open",
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
	}

	if n > 0 {
		service.Banner = string(buffer[:n])
		service.Service, service.Version = m.identifyService(port, service.Banner)
	} else {
		service.Service = m.getCommonServiceName(port, "udp")
	}

	service.RiskLevel = m.assessServiceRisk(service)
	return service
}

// grabTCPBanner attempts to grab service banner
func (m *PortServiceDiscoveryModule) grabTCPBanner(conn net.Conn, port int) string {
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Send protocol-specific probes
	switch port {
	case 80, 8080:
		// HTTP probe
		conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	case 443, 8443:
		// HTTPS - just try to read banner
		// Don't send anything, just read
	case 22:
		// SSH - service typically sends banner first
		// Don't send anything, just read
	case 23:
		// Telnet - read initial negotiation
		// Don't send anything, just read
	default:
		// Generic probe - just try to read
		// Don't send anything, just read
	}

	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return ""
	}

	// Clean up banner text
	banner := strings.TrimSpace(string(buffer[:n]))
	return banner
}

// getUDPProbe returns appropriate UDP probe for specific ports
func (m *PortServiceDiscoveryModule) getUDPProbe(port int) []byte {
	switch port {
	case 53:
		// DNS query probe
		return []byte{
			0x12, 0x34, // Transaction ID
			0x01, 0x00, // Flags (standard query)
			0x00, 0x01, // Questions
			0x00, 0x00, // Answer RRs
			0x00, 0x00, // Authority RRs
			0x00, 0x00, // Additional RRs
			// Query for "." A record
			0x00,       // Root domain
			0x00, 0x01, // Type A
			0x00, 0x01, // Class IN
		}
	case 161:
		// SNMP GetRequest probe (public community)
		return []byte{
			0x30, 0x19, // SEQUENCE
			0x02, 0x01, 0x00, // Version 1
			0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // Community "public"
			0xa0, 0x0c, // GetRequest
			0x02, 0x01, 0x01, // Request ID
			0x02, 0x01, 0x00, // Error Status
			0x02, 0x01, 0x00, // Error Index
			0x30, 0x00, // VarBindList (empty)
		}
	case 123:
		// NTP probe
		return []byte{
			0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
	default:
		// Generic UDP probe
		return []byte{0x00}
	}
}

// identifyService attempts to identify service and version from banner
func (m *PortServiceDiscoveryModule) identifyService(port int, banner string) (service, version string) {
	banner = strings.ToLower(banner)

	// SSH identification
	if strings.Contains(banner, "ssh") {
		service = "SSH"
		if idx := strings.Index(banner, "openssh"); idx != -1 {
			version = m.extractVersion(banner[idx:])
		}
		return
	}

	// HTTP identification
	if strings.Contains(banner, "http") {
		service = "HTTP"
		if strings.Contains(banner, "apache") {
			service = "Apache HTTP"
			version = m.extractVersion(banner)
		} else if strings.Contains(banner, "nginx") {
			service = "Nginx"
			version = m.extractVersion(banner)
		} else if strings.Contains(banner, "iis") {
			service = "IIS"
			version = m.extractVersion(banner)
		}
		return
	}

	// FTP identification
	if strings.Contains(banner, "ftp") {
		service = "FTP"
		version = m.extractVersion(banner)
		return
	}

	// Telnet identification
	if port == 23 {
		service = "Telnet"
		return
	}

	// SMB identification
	if port == 445 || port == 139 {
		service = "SMB"
		return
	}

	// RDP identification
	if port == 3389 {
		service = "RDP"
		return
	}

	// Default to common service names
	service = m.getCommonServiceName(port, "tcp")
	return
}

// extractVersion attempts to extract version from banner
func (m *PortServiceDiscoveryModule) extractVersion(banner string) string {
	// Simple version extraction - look for version patterns
	parts := strings.Fields(banner)
	for _, part := range parts {
		if strings.Contains(part, ".") && len(part) > 2 {
			// Looks like a version number
			return part
		}
	}
	return "unknown"
}

// getCommonServiceName returns common service name for port
func (m *PortServiceDiscoveryModule) getCommonServiceName(port int, protocol string) string {
	commonServices := map[int]string{
		22:    "SSH",
		23:    "Telnet",
		53:    "DNS",
		80:    "HTTP",
		88:    "Kerberos",
		110:   "POP3",
		135:   "RPC",
		139:   "NetBIOS",
		143:   "IMAP",
		161:   "SNMP",
		389:   "LDAP",
		443:   "HTTPS",
		445:   "SMB",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "MSSQL",
		1521:  "Oracle",
		2049:  "NFS",
		3306:  "MySQL",
		3389:  "RDP",
		5900:  "VNC",
		8080:  "HTTP-Alt",
		8443:  "HTTPS-Alt",
		27017: "MongoDB",
	}

	if service, exists := commonServices[port]; exists {
		return service
	}
	return "Unknown"
}

// assessServiceRisk determines risk level for discovered service
func (m *PortServiceDiscoveryModule) assessServiceRisk(service *ServiceFingerprint) string {
	// High risk services
	highRiskServices := map[string]bool{
		"telnet":   true,
		"ftp":      true,
		"rcp":      true,
		"rsh":      true,
		"netbios":  true,
	}

	// High risk ports
	highRiskPorts := map[int]bool{
		23:   true, // Telnet
		21:   true, // FTP
		135:  true, // RPC
		139:  true, // NetBIOS
		445:  true, // SMB
		3389: true, // RDP (if exposed)
	}

	serviceLower := strings.ToLower(service.Service)

	if highRiskServices[serviceLower] || highRiskPorts[service.Port] {
		return "HIGH"
	}

	// Medium risk for management interfaces
	if service.Port == 161 || service.Port == 22 || service.Port == 3306 || service.Port == 1433 {
		return "MEDIUM"
	}

	// Low risk for standard web services
	if service.Port == 80 || service.Port == 443 {
		return "LOW"
	}

	return "MEDIUM" // Default to medium for unknown services
}

// calculateRiskScore calculates overall risk score based on discovered services
func (m *PortServiceDiscoveryModule) calculateRiskScore(result *ScanResult) float64 {
	if len(result.Services) == 0 {
		return 5.0 // Very low risk if no services found
	}

	highRiskCount := 0
	mediumRiskCount := 0
	lowRiskCount := 0

	for _, service := range result.Services {
		switch service.RiskLevel {
		case "HIGH":
			highRiskCount++
		case "MEDIUM":
			mediumRiskCount++
		case "LOW":
			lowRiskCount++
		}
	}

	// Calculate weighted score
	score := float64(highRiskCount)*25 + float64(mediumRiskCount)*10 + float64(lowRiskCount)*2

	// Normalize to 0-100 scale (assume max 20 services)
	maxScore := 20 * 25 // All high risk
	normalizedScore := (score / float64(maxScore)) * 100

	if normalizedScore > 100 {
		normalizedScore = 100
	}

	return normalizedScore
}

// countHighRiskServices counts services with high risk level
func (m *PortServiceDiscoveryModule) countHighRiskServices(services []ServiceFingerprint) int {
	count := 0
	for _, service := range services {
		if service.RiskLevel == "HIGH" {
			count++
		}
	}
	return count
}

// generateSummary creates a human-readable summary
func (m *PortServiceDiscoveryModule) generateSummary(result *ScanResult) string {
	if len(result.Services) == 0 {
		return "No accessible network services discovered on local network"
	}

	highRiskCount := m.countHighRiskServices(result.Services)

	summary := fmt.Sprintf("Discovered %d network services across %d active hosts",
		len(result.Services), len(result.ActiveHosts))

	if highRiskCount > 0 {
		summary += fmt.Sprintf(", including %d high-risk services requiring immediate attention", highRiskCount)
	}

	return summary
}

// generateRecommendations creates actionable recommendations
func (m *PortServiceDiscoveryModule) generateRecommendations(result *ScanResult) []string {
	recommendations := []string{}

	highRiskCount := m.countHighRiskServices(result.Services)

	if highRiskCount > 0 {
		recommendations = append(recommendations,
			"Immediately secure or disable high-risk services (Telnet, FTP, unprotected SMB)",
			"Implement network segmentation to isolate critical services",
			"Enable firewall rules to restrict access to management ports")
	}

	if len(result.Services) > 10 {
		recommendations = append(recommendations,
			"Review all discovered services and disable unnecessary ones",
			"Implement principle of least privilege for network access")
	}

	recommendations = append(recommendations,
		"Regularly monitor network services for changes",
		"Implement intrusion detection for network scanning activities",
		"Keep all network services updated with latest security patches")

	return recommendations
}

// Plugin constructor for auto-registration
func NewPortServiceDiscoveryModulePlugin(logger *logger.Logger) modules.ModulePlugin {
	return NewPortServiceDiscoveryModule(logger)
}

// Auto-registration via init() function
func init() {
	modules.RegisterPluginConstructor("PORT_SERVICE_DISCOVERY", NewPortServiceDiscoveryModulePlugin)
}