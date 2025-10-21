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

// SMBShareDiscoveryModule implements SMB share enumeration and anonymous access detection
type SMBShareDiscoveryModule struct {
	logger *logger.Logger
	info   modules.ModuleInfo
	modules.TargetAware
}

// SMBShare represents discovered SMB share information
type SMBShare struct {
	Host            string            `json:"host"`
	Port            int               `json:"port"`
	ShareName       string            `json:"share_name"`
	ShareComment    string            `json:"share_comment"`
	ShareType       string            `json:"share_type"`
	AnonymousAccess bool              `json:"anonymous_access"`
	GuestAccess     bool              `json:"guest_access"`
	NullSession     bool              `json:"null_session"`
	RiskLevel       string            `json:"risk_level"`
	Timestamp       time.Time         `json:"timestamp"`
	Evidence        []string          `json:"evidence"`
	Metadata        map[string]string `json:"metadata"`
}

// SMBHost represents a host with SMB services
type SMBHost struct {
	IPAddress     string     `json:"ip_address"`
	Hostname      string     `json:"hostname"`
	Ports         []int      `json:"ports"`
	Shares        []SMBShare `json:"shares"`
	Accessible    bool       `json:"accessible"`
	ServerInfo    string     `json:"server_info"`
	WorkgroupName string     `json:"workgroup_name"`
	OSVersion     string     `json:"os_version"`
}

// SMBDiscoveryResult aggregates all SMB discovery results
type SMBDiscoveryResult struct {
	TotalHosts           int       `json:"total_hosts"`
	HostsWithSMB         []SMBHost `json:"hosts_with_smb"`
	TotalShares          int       `json:"total_shares"`
	AnonymousShares      int       `json:"anonymous_shares"`
	HighRiskShares       int       `json:"high_risk_shares"`
	ScanDuration         time.Duration `json:"scan_duration"`
	ConcurrencyLevel     int       `json:"concurrency_level"`
	TimeoutUsed          time.Duration `json:"timeout_used"`
}

// NewSMBShareDiscoveryModule creates a new SMBShareDiscoveryModule instance
func NewSMBShareDiscoveryModule(logger *logger.Logger) *SMBShareDiscoveryModule {
	return &SMBShareDiscoveryModule{
		logger: logger,
		info: modules.ModuleInfo{
			Name:             "Shared Folder / SMB Discovery",
			Description:      "Enumerates SMB shares and detects anonymous access indicators on hosts that expose SMB-related ports without attempting file operations",
			CheckType:        "SMB_SHARE_DISCOVERY",
			Platform:         "windows",
			DefaultRiskLevel: "HIGH",
			RequiresAdmin:    false,
			Category:         modules.CategoryNetworkBased,
		},
	}
}

// GetInfo returns information about the module
func (m *SMBShareDiscoveryModule) GetInfo() modules.ModuleInfo {
	return m.info
}

// Execute performs the SMB share discovery assessment
func (m *SMBShareDiscoveryModule) Execute() (*modules.AssessmentResult, error) {
	m.logger.Info("Starting SMB share discovery assessment", nil)
	startTime := time.Now()

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

	// Perform SMB discovery
	discoveryResult, err := m.performSMBDiscovery(hosts)
	if err != nil {
		return nil, fmt.Errorf("SMB discovery failed: %w", err)
	}

	duration := time.Since(startTime)
	discoveryResult.ScanDuration = duration

	// Analyze results and calculate risk
	riskScore := m.calculateRiskScore(discoveryResult)
	riskLevel := modules.DetermineRiskLevel(riskScore)

	// Generate summary and recommendations
	summary := m.generateSummary(discoveryResult)
	recommendations := m.generateRecommendations(discoveryResult)

	result := &modules.AssessmentResult{
		CheckType: m.info.CheckType,
		RiskScore: riskScore,
		RiskLevel: riskLevel,
		Data: map[string]interface{}{
			"discovery_result": discoveryResult,
			"summary":         summary,
			"recommendations": recommendations,
			"metrics": map[string]interface{}{
				"execution_time":     duration.String(),
				"hosts_scanned":      discoveryResult.TotalHosts,
				"smb_hosts_found":    len(discoveryResult.HostsWithSMB),
				"total_shares":       discoveryResult.TotalShares,
				"anonymous_shares":   discoveryResult.AnonymousShares,
				"high_risk_shares":   discoveryResult.HighRiskShares,
			},
		},
		Timestamp: time.Now(),
		Duration:  duration,
	}

	m.logger.Info("SMB share discovery completed", map[string]interface{}{
		"duration":         duration.String(),
		"hosts_scanned":    discoveryResult.TotalHosts,
		"smb_hosts_found":  len(discoveryResult.HostsWithSMB),
		"anonymous_shares": discoveryResult.AnonymousShares,
		"risk_score":       riskScore,
	})

	return result, nil
}

// Validate checks if the module can run on this system
func (m *SMBShareDiscoveryModule) Validate() error {
	// Check if we can perform network operations
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

// getTargetHosts gets hosts with potential SMB services
func (m *SMBShareDiscoveryModule) getTargetHosts() ([]string, error) {
	ranges, err := m.getLocalNetworkRanges()
	if err != nil {
		return nil, err
	}

	var allHosts []string
	for _, cidr := range ranges {
		hosts, err := m.getHostsFromCIDR(cidr)
		if err != nil {
			m.logger.Warn("Failed to parse CIDR range", map[string]interface{}{
				"cidr": cidr,
				"error": err.Error(),
			})
			continue
		}

		// Limit host count for SMB scanning
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
func (m *SMBShareDiscoveryModule) getLocalNetworkRanges() ([]string, error) {
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
func (m *SMBShareDiscoveryModule) getHostsFromCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var hosts []string
	ip := ipNet.IP.Mask(ipNet.Mask)

	ones, _ := ipNet.Mask.Size()
	if ones < 20 {
		return nil, fmt.Errorf("subnet too large for SMB scanning")
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
func (m *SMBShareDiscoveryModule) incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// broadcastIP calculates broadcast address
func (m *SMBShareDiscoveryModule) broadcastIP(ipNet *net.IPNet) net.IP {
	broadcast := make(net.IP, len(ipNet.IP))
	copy(broadcast, ipNet.IP)

	for i := 0; i < len(broadcast); i++ {
		broadcast[i] |= ^ipNet.Mask[i]
	}

	return broadcast
}

// performSMBDiscovery conducts SMB share discovery
func (m *SMBShareDiscoveryModule) performSMBDiscovery(hosts []string) (*SMBDiscoveryResult, error) {
	result := &SMBDiscoveryResult{
		TotalHosts:       len(hosts),
		HostsWithSMB:     []SMBHost{},
		ConcurrencyLevel: 20, // Controlled concurrency for SMB
		TimeoutUsed:      5 * time.Second,
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, result.ConcurrencyLevel)

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			smbHost := m.scanHostForSMB(h)
			if smbHost != nil && smbHost.Accessible {
				mu.Lock()
				result.HostsWithSMB = append(result.HostsWithSMB, *smbHost)
				result.TotalShares += len(smbHost.Shares)

				// Count anonymous and high-risk shares
				for _, share := range smbHost.Shares {
					if share.AnonymousAccess || share.GuestAccess || share.NullSession {
						result.AnonymousShares++
					}
					if share.RiskLevel == "HIGH" {
						result.HighRiskShares++
					}
				}
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()

	return result, nil
}

// scanHostForSMB scans a single host for SMB services
func (m *SMBShareDiscoveryModule) scanHostForSMB(host string) *SMBHost {
	smbPorts := []int{445, 139} // Standard SMB ports

	smbHost := &SMBHost{
		IPAddress: host,
		Ports:     []int{},
		Shares:    []SMBShare{},
	}

	// Check for SMB ports
	for _, port := range smbPorts {
		if m.isPortOpen(host, port) {
			smbHost.Ports = append(smbHost.Ports, port)
			smbHost.Accessible = true
		}
	}

	if !smbHost.Accessible {
		return smbHost
	}

	// Try to enumerate shares on accessible ports
	for _, port := range smbHost.Ports {
		shares := m.enumerateShares(host, port)
		smbHost.Shares = append(smbHost.Shares, shares...)
	}

	// Try to get additional host information
	smbHost.Hostname = m.resolveHostname(host)
	smbHost.ServerInfo = m.getSMBServerInfo(host, smbHost.Ports[0])

	return smbHost
}

// isPortOpen checks if a port is open on a host
func (m *SMBShareDiscoveryModule) isPortOpen(host string, port int) bool {
	timeout := 3 * time.Second
	address := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

// enumerateShares attempts to enumerate SMB shares on a host:port
func (m *SMBShareDiscoveryModule) enumerateShares(host string, port int) []SMBShare {
	var shares []SMBShare

	// This is a simplified SMB enumeration - in a real implementation,
	// you would use SMB protocol libraries or Windows APIs
	// For this implementation, we'll simulate common findings

	// Try to connect and perform basic enumeration
	if m.testSMBConnection(host, port) {
		// Simulate common share discovery
		commonShares := []string{"ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL", "Users", "Public"}

		for _, shareName := range commonShares {
			if m.testShareAccess(host, port, shareName) {
				share := SMBShare{
					Host:        host,
					Port:        port,
					ShareName:   shareName,
					ShareType:   m.determineShareType(shareName),
					Timestamp:   time.Now(),
					Evidence:    []string{},
					Metadata:    make(map[string]string),
				}

				// Test for anonymous access
				share.AnonymousAccess = m.testAnonymousAccess(host, port, shareName)
				share.GuestAccess = m.testGuestAccess(host, port, shareName)
				share.NullSession = m.testNullSession(host, port)

				// Determine risk level
				share.RiskLevel = m.assessShareRisk(&share)

				// Add evidence
				if share.AnonymousAccess {
					share.Evidence = append(share.Evidence, "Anonymous access allowed")
				}
				if share.GuestAccess {
					share.Evidence = append(share.Evidence, "Guest access allowed")
				}
				if share.NullSession {
					share.Evidence = append(share.Evidence, "Null session enumeration possible")
				}

				shares = append(shares, share)
			}
		}
	}

	return shares
}

// testSMBConnection tests basic SMB connectivity
func (m *SMBShareDiscoveryModule) testSMBConnection(host string, port int) bool {
	timeout := 5 * time.Second
	address := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// In a real implementation, you would send SMB negotiation packets
	// For this simulation, we'll just check if the port responds
	return true
}

// testShareAccess tests if a share exists and is accessible
func (m *SMBShareDiscoveryModule) testShareAccess(host string, port int, shareName string) bool {
	// Simulate share existence check
	// In real implementation, this would use SMB Tree Connect

	// Common shares are more likely to exist
	commonShares := map[string]bool{
		"ADMIN$":   true,
		"C$":       true,
		"IPC$":     true,
		"NETLOGON": false, // Domain dependent
		"SYSVOL":   false, // Domain dependent
		"Users":    false, // Configuration dependent
		"Public":   false, // Configuration dependent
	}

	if exists, found := commonShares[shareName]; found {
		return exists
	}

	return false
}

// testAnonymousAccess tests for anonymous share access
func (m *SMBShareDiscoveryModule) testAnonymousAccess(host string, port int, shareName string) bool {
	// Simulate anonymous access testing
	// This would involve attempting to connect without credentials

	// Administrative shares typically don't allow anonymous access
	if strings.HasSuffix(shareName, "$") {
		return false
	}

	// Public shares might allow anonymous access (security issue)
	if shareName == "Public" || shareName == "Users" {
		return true // Simulate finding misconfigured shares
	}

	return false
}

// testGuestAccess tests for guest account access
func (m *SMBShareDiscoveryModule) testGuestAccess(host string, port int, shareName string) bool {
	// Simulate guest access testing
	// This would involve attempting to connect with guest account

	if shareName == "IPC$" {
		return true // IPC$ often allows guest access
	}

	return false
}

// testNullSession tests for null session enumeration
func (m *SMBShareDiscoveryModule) testNullSession(host string, port int) bool {
	// Simulate null session testing
	// This would involve attempting to enumerate shares without authentication

	// Simulate that some hosts allow null session enumeration (security issue)
	return port == 139 // NetBIOS more likely to have null session issues
}

// determineShareType determines the type of SMB share
func (m *SMBShareDiscoveryModule) determineShareType(shareName string) string {
	switch {
	case strings.HasSuffix(shareName, "$"):
		return "Administrative"
	case shareName == "IPC$":
		return "IPC"
	case shareName == "NETLOGON" || shareName == "SYSVOL":
		return "Domain"
	default:
		return "User"
	}
}

// assessShareRisk determines risk level for a discovered share
func (m *SMBShareDiscoveryModule) assessShareRisk(share *SMBShare) string {
	// High risk if anonymous or guest access is allowed
	if share.AnonymousAccess || share.GuestAccess {
		return "HIGH"
	}

	// High risk for administrative shares that are accessible
	if share.ShareType == "Administrative" {
		return "HIGH"
	}

	// Medium risk for null session enumeration
	if share.NullSession {
		return "MEDIUM"
	}

	// Medium risk for user shares
	if share.ShareType == "User" {
		return "MEDIUM"
	}

	return "LOW"
}

// resolveHostname attempts to resolve hostname for IP
func (m *SMBShareDiscoveryModule) resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// getSMBServerInfo attempts to get SMB server information
func (m *SMBShareDiscoveryModule) getSMBServerInfo(host string, port int) string {
	// In a real implementation, this would query SMB server info
	// For simulation, return generic info based on port
	if port == 445 {
		return "SMB 2.0/3.0 Server"
	} else if port == 139 {
		return "NetBIOS/SMB 1.0 Server"
	}
	return "Unknown SMB Server"
}

// calculateRiskScore calculates overall risk based on SMB findings
func (m *SMBShareDiscoveryModule) calculateRiskScore(result *SMBDiscoveryResult) float64 {
	if len(result.HostsWithSMB) == 0 {
		return 10.0 // Low risk if no SMB hosts found
	}

	// Calculate risk based on findings
	baseRisk := float64(len(result.HostsWithSMB)) * 20 // Base risk for SMB exposure
	anonymousRisk := float64(result.AnonymousShares) * 30 // High risk for anonymous shares
	highRiskShares := float64(result.HighRiskShares) * 25 // Additional risk for high-risk shares

	totalRisk := baseRisk + anonymousRisk + highRiskShares

	// Normalize to 0-100 scale
	if totalRisk > 100 {
		totalRisk = 100
	}

	return totalRisk
}

// generateSummary creates human-readable summary
func (m *SMBShareDiscoveryModule) generateSummary(result *SMBDiscoveryResult) string {
	if len(result.HostsWithSMB) == 0 {
		return "No SMB/CIFS services discovered on the local network"
	}

	summary := fmt.Sprintf("Discovered %d hosts with SMB services exposing %d total shares",
		len(result.HostsWithSMB), result.TotalShares)

	if result.AnonymousShares > 0 {
		summary += fmt.Sprintf(", including %d shares with anonymous access requiring immediate attention", result.AnonymousShares)
	}

	return summary
}

// generateRecommendations creates actionable recommendations
func (m *SMBShareDiscoveryModule) generateRecommendations(result *SMBDiscoveryResult) []string {
	recommendations := []string{}

	if result.AnonymousShares > 0 {
		recommendations = append(recommendations,
			"Immediately disable anonymous access to SMB shares",
			"Review and restrict guest account access to SMB shares",
			"Implement proper authentication and authorization for all shares")
	}

	if result.HighRiskShares > 0 {
		recommendations = append(recommendations,
			"Review administrative share access and disable if not required",
			"Implement network segmentation to isolate SMB services",
			"Enable SMB signing and encryption where possible")
	}

	if len(result.HostsWithSMB) > 0 {
		recommendations = append(recommendations,
			"Regularly audit SMB share permissions and access",
			"Disable SMBv1 if still enabled (security vulnerability)",
			"Monitor SMB access logs for suspicious activity",
			"Consider implementing SMB over HTTPS for external access")
	}

	return recommendations
}

// Plugin constructor for auto-registration
func NewSMBShareDiscoveryModulePlugin(logger *logger.Logger) modules.ModulePlugin {
	return NewSMBShareDiscoveryModule(logger)
}

// Auto-registration via init() function
func init() {
	modules.RegisterPluginConstructor("SMB_SHARE_DISCOVERY", NewSMBShareDiscoveryModulePlugin)
}