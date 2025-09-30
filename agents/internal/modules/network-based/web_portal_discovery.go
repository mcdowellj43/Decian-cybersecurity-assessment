package networkbased

import (
	"crypto/tls"
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// WebPortalDiscoveryModule implements web admin console and device portal discovery
type WebPortalDiscoveryModule struct {
	logger *logger.Logger
	info   modules.ModuleInfo
}

// WebPortal represents discovered web portal information
type WebPortal struct {
	Host            string            `json:"host"`
	Port            int               `json:"port"`
	Protocol        string            `json:"protocol"`
	URL             string            `json:"url"`
	Title           string            `json:"title"`
	ServerHeader    string            `json:"server_header"`
	StatusCode      int               `json:"status_code"`
	ResponseSize    int               `json:"response_size"`
	DeviceType      string            `json:"device_type"`
	DeviceBrand     string            `json:"device_brand"`
	IsDefaultPage   bool              `json:"is_default_page"`
	IsAdminPortal   bool              `json:"is_admin_portal"`
	IsDevicePortal  bool              `json:"is_device_portal"`
	RiskLevel       string            `json:"risk_level"`
	Timestamp       time.Time         `json:"timestamp"`
	Evidence        []string          `json:"evidence"`
	AdminPaths      []string          `json:"admin_paths"`
	Metadata        map[string]string `json:"metadata"`
}

// WebDiscoveryResult aggregates all web portal discovery results
type WebDiscoveryResult struct {
	TotalHosts         int         `json:"total_hosts"`
	HostsWithWeb       []string    `json:"hosts_with_web"`
	WebPortals         []WebPortal `json:"web_portals"`
	DefaultPages       int         `json:"default_pages"`
	AdminPortals       int         `json:"admin_portals"`
	DevicePortals      int         `json:"device_portals"`
	HighRiskPortals    int         `json:"high_risk_portals"`
	ScanDuration       time.Duration `json:"scan_duration"`
	ConcurrencyLevel   int         `json:"concurrency_level"`
	TimeoutUsed        time.Duration `json:"timeout_used"`
}

// DevicePattern represents device identification patterns
type DevicePattern struct {
	Brand       string
	DeviceType  string
	TitleRegex  *regexp.Regexp
	ServerRegex *regexp.Regexp
	BodyRegex   *regexp.Regexp
}

// NewWebPortalDiscoveryModule creates a new WebPortalDiscoveryModule instance
func NewWebPortalDiscoveryModule(logger *logger.Logger) *WebPortalDiscoveryModule {
	return &WebPortalDiscoveryModule{
		logger: logger,
		info: modules.ModuleInfo{
			Name:             "Default Web Page / Device Portal Check",
			Description:      "Discovers web admin consoles, default web pages, and device portals that expose login pages or management interfaces without attempting authentication",
			CheckType:        "WEB_PORTAL_DISCOVERY",
			Platform:         "windows",
			DefaultRiskLevel: "MEDIUM",
			RequiresAdmin:    false,
			Category:         modules.CategoryNetworkBased,
		},
	}
}

// GetInfo returns information about the module
func (m *WebPortalDiscoveryModule) GetInfo() modules.ModuleInfo {
	return m.info
}

// Execute performs the web portal discovery assessment
func (m *WebPortalDiscoveryModule) Execute() (*modules.AssessmentResult, error) {
	m.logger.Info("Starting web portal discovery assessment", nil)
	startTime := time.Now()

	// Get target hosts from local network
	hosts, err := m.getTargetHosts()
	if err != nil {
		return nil, fmt.Errorf("failed to determine target hosts: %w", err)
	}

	// Perform web portal discovery
	discoveryResult, err := m.performWebDiscovery(hosts)
	if err != nil {
		return nil, fmt.Errorf("web portal discovery failed: %w", err)
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
				"web_hosts_found":    len(discoveryResult.HostsWithWeb),
				"portals_found":      len(discoveryResult.WebPortals),
				"default_pages":      discoveryResult.DefaultPages,
				"admin_portals":      discoveryResult.AdminPortals,
				"device_portals":     discoveryResult.DevicePortals,
				"high_risk_portals":  discoveryResult.HighRiskPortals,
			},
		},
		Timestamp: time.Now(),
		Duration:  duration,
	}

	m.logger.Info("Web portal discovery completed", map[string]interface{}{
		"duration":         duration.String(),
		"hosts_scanned":    discoveryResult.TotalHosts,
		"portals_found":    len(discoveryResult.WebPortals),
		"admin_portals":    discoveryResult.AdminPortals,
		"device_portals":   discoveryResult.DevicePortals,
		"risk_score":       riskScore,
	})

	return result, nil
}

// Validate checks if the module can run on this system
func (m *WebPortalDiscoveryModule) Validate() error {
	// Check if we can perform HTTP requests
	client := &http.Client{Timeout: 2 * time.Second}
	_, err := client.Get("http://httpbin.org/status/200")
	if err != nil {
		// This is expected to fail in isolated environments
		m.logger.Debug("HTTP connectivity test failed (expected in isolated environments)", map[string]interface{}{
			"error": err.Error(),
		})
	}

	return nil
}

// getTargetHosts gets hosts from local network for web scanning
func (m *WebPortalDiscoveryModule) getTargetHosts() ([]string, error) {
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

		// Limit host count for web scanning
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
func (m *WebPortalDiscoveryModule) getLocalNetworkRanges() ([]string, error) {
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
func (m *WebPortalDiscoveryModule) getHostsFromCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var hosts []string
	ip := ipNet.IP.Mask(ipNet.Mask)

	ones, _ := ipNet.Mask.Size()
	if ones < 20 {
		return nil, fmt.Errorf("subnet too large for web scanning")
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
func (m *WebPortalDiscoveryModule) incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// broadcastIP calculates broadcast address
func (m *WebPortalDiscoveryModule) broadcastIP(ipNet *net.IPNet) net.IP {
	broadcast := make(net.IP, len(ipNet.IP))
	copy(broadcast, ipNet.IP)

	for i := 0; i < len(broadcast); i++ {
		broadcast[i] |= ^ipNet.Mask[i]
	}

	return broadcast
}

// performWebDiscovery conducts web portal discovery
func (m *WebPortalDiscoveryModule) performWebDiscovery(hosts []string) (*WebDiscoveryResult, error) {
	result := &WebDiscoveryResult{
		TotalHosts:       len(hosts),
		HostsWithWeb:     []string{},
		WebPortals:       []WebPortal{},
		ConcurrencyLevel: 20, // Controlled concurrency for web requests
		TimeoutUsed:      5 * time.Second,
	}

	// Common web ports to check
	webPorts := []int{80, 443, 8080, 8443, 8000, 8888, 9000, 3000, 5000, 8081, 8082, 9001}

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, result.ConcurrencyLevel)

	hostWebMap := make(map[string]bool)

	for _, host := range hosts {
		for _, port := range webPorts {
			wg.Add(1)
			go func(h string, p int) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				portal := m.scanWebPortal(h, p)
				if portal != nil {
					mu.Lock()
					result.WebPortals = append(result.WebPortals, *portal)

					// Track unique hosts with web services
					if !hostWebMap[h] {
						result.HostsWithWeb = append(result.HostsWithWeb, h)
						hostWebMap[h] = true
					}

					// Count portal types
					if portal.IsDefaultPage {
						result.DefaultPages++
					}
					if portal.IsAdminPortal {
						result.AdminPortals++
					}
					if portal.IsDevicePortal {
						result.DevicePortals++
					}
					if portal.RiskLevel == "HIGH" {
						result.HighRiskPortals++
					}

					mu.Unlock()
				}
			}(host, port)
		}
	}

	wg.Wait()

	return result, nil
}

// scanWebPortal scans a single host:port for web portals
func (m *WebPortalDiscoveryModule) scanWebPortal(host string, port int) *WebPortal {
	// Try both HTTP and HTTPS
	protocols := []string{"http", "https"}

	for _, protocol := range protocols {
		if portal := m.fetchWebPortal(host, port, protocol); portal != nil {
			return portal
		}
	}

	return nil
}

// fetchWebPortal fetches and analyzes a web portal
func (m *WebPortalDiscoveryModule) fetchWebPortal(host string, port int, protocol string) *WebPortal {
	url := fmt.Sprintf("%s://%s:%d/", protocol, host, port)

	// Create HTTP client with reasonable timeouts and security settings
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For device discovery, we need to accept self-signed certs
			},
			DisableKeepAlives: true,
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Read response body (limited size)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10240)) // 10KB limit
	if err != nil {
		return nil
	}

	portal := &WebPortal{
		Host:         host,
		Port:         port,
		Protocol:     protocol,
		URL:          url,
		StatusCode:   resp.StatusCode,
		ResponseSize: len(body),
		Timestamp:    time.Now(),
		Evidence:     []string{},
		AdminPaths:   []string{},
		Metadata:     make(map[string]string),
	}

	// Extract server header
	portal.ServerHeader = resp.Header.Get("Server")

	// Extract page title
	portal.Title = m.extractTitle(string(body))

	// Store response headers as metadata
	for key, values := range resp.Header {
		if len(values) > 0 {
			portal.Metadata[strings.ToLower(key)] = values[0]
		}
	}

	// Analyze the portal
	m.analyzePortal(portal, string(body))

	// Determine risk level
	portal.RiskLevel = m.assessPortalRisk(portal)

	return portal
}

// extractTitle extracts the page title from HTML
func (m *WebPortalDiscoveryModule) extractTitle(body string) string {
	titleRegex := regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// analyzePortal analyzes the portal to determine its type and characteristics
func (m *WebPortalDiscoveryModule) analyzePortal(portal *WebPortal, body string) {
	bodyLower := strings.ToLower(body)
	titleLower := strings.ToLower(portal.Title)
	serverLower := strings.ToLower(portal.ServerHeader)

	// Check for device portals using known patterns
	devicePatterns := m.getDevicePatterns()
	for _, pattern := range devicePatterns {
		if (pattern.TitleRegex != nil && pattern.TitleRegex.MatchString(titleLower)) ||
			(pattern.ServerRegex != nil && pattern.ServerRegex.MatchString(serverLower)) ||
			(pattern.BodyRegex != nil && pattern.BodyRegex.MatchString(bodyLower)) {

			portal.IsDevicePortal = true
			portal.DeviceBrand = pattern.Brand
			portal.DeviceType = pattern.DeviceType
			portal.Evidence = append(portal.Evidence, fmt.Sprintf("Detected %s %s device", pattern.Brand, pattern.DeviceType))
			break
		}
	}

	// Check for admin portals
	adminIndicators := []string{
		"admin", "administrator", "management", "config", "configuration",
		"control panel", "web interface", "login", "sign in", "authentication",
		"router", "switch", "firewall", "gateway", "access point",
	}

	for _, indicator := range adminIndicators {
		if strings.Contains(titleLower, indicator) || strings.Contains(bodyLower, indicator) {
			portal.IsAdminPortal = true
			portal.Evidence = append(portal.Evidence, fmt.Sprintf("Contains admin keyword: %s", indicator))
		}
	}

	// Check for default pages
	defaultIndicators := []string{
		"default", "welcome", "index", "home page", "test page",
		"apache", "nginx", "iis", "lighttpd", "it works",
		"welcome to", "default web site", "server default page",
	}

	for _, indicator := range defaultIndicators {
		if strings.Contains(titleLower, indicator) || strings.Contains(bodyLower, indicator) {
			portal.IsDefaultPage = true
			portal.Evidence = append(portal.Evidence, fmt.Sprintf("Contains default page indicator: %s", indicator))
		}
	}

	// Check for common admin paths
	adminPaths := []string{
		"/admin", "/administrator", "/management", "/config", "/login",
		"/signin", "/auth", "/control", "/panel", "/dashboard",
	}

	for _, path := range adminPaths {
		if strings.Contains(bodyLower, `href="`+path) || strings.Contains(bodyLower, `action="`+path) {
			portal.AdminPaths = append(portal.AdminPaths, path)
			portal.Evidence = append(portal.Evidence, fmt.Sprintf("Found admin path: %s", path))
		}
	}

	// Additional analysis based on server header
	if serverLower != "" {
		portal.Evidence = append(portal.Evidence, fmt.Sprintf("Server: %s", portal.ServerHeader))
	}

	// Check response code
	if portal.StatusCode == 401 || portal.StatusCode == 403 {
		portal.Evidence = append(portal.Evidence, fmt.Sprintf("Authentication required (HTTP %d)", portal.StatusCode))
		portal.IsAdminPortal = true
	}
}

// getDevicePatterns returns device identification patterns
func (m *WebPortalDiscoveryModule) getDevicePatterns() []DevicePattern {
	return []DevicePattern{
		// Routers
		{
			Brand:      "Linksys",
			DeviceType: "Router",
			TitleRegex: regexp.MustCompile(`linksys|smart wi-fi`),
			ServerRegex: regexp.MustCompile(`linksys`),
		},
		{
			Brand:      "Netgear",
			DeviceType: "Router",
			TitleRegex: regexp.MustCompile(`netgear|routerlogin`),
			ServerRegex: regexp.MustCompile(`netgear`),
		},
		{
			Brand:      "TP-Link",
			DeviceType: "Router",
			TitleRegex: regexp.MustCompile(`tp-link|tplink`),
			ServerRegex: regexp.MustCompile(`tp-link`),
		},
		{
			Brand:      "D-Link",
			DeviceType: "Router",
			TitleRegex: regexp.MustCompile(`d-link|dlink`),
			ServerRegex: regexp.MustCompile(`d-link`),
		},
		// Cameras
		{
			Brand:      "Axis",
			DeviceType: "Camera",
			TitleRegex: regexp.MustCompile(`axis.*camera|live view`),
			ServerRegex: regexp.MustCompile(`axis`),
		},
		{
			Brand:      "Hikvision",
			DeviceType: "Camera",
			TitleRegex: regexp.MustCompile(`hikvision|web components`),
			ServerRegex: regexp.MustCompile(`hikvision`),
		},
		// Printers
		{
			Brand:      "HP",
			DeviceType: "Printer",
			TitleRegex: regexp.MustCompile(`hp.*printer|embedded web server`),
			ServerRegex: regexp.MustCompile(`hp http server`),
		},
		{
			Brand:      "Canon",
			DeviceType: "Printer",
			TitleRegex: regexp.MustCompile(`canon.*printer|remote ui`),
			ServerRegex: regexp.MustCompile(`canon`),
		},
		// Network devices
		{
			Brand:      "Cisco",
			DeviceType: "Network Device",
			TitleRegex: regexp.MustCompile(`cisco|catalyst|aironet`),
			ServerRegex: regexp.MustCompile(`cisco`),
		},
		{
			Brand:      "Ubiquiti",
			DeviceType: "Access Point",
			TitleRegex: regexp.MustCompile(`ubiquiti|unifi|airmax`),
			ServerRegex: regexp.MustCompile(`ubiquiti`),
		},
	}
}

// assessPortalRisk determines risk level for discovered portal
func (m *WebPortalDiscoveryModule) assessPortalRisk(portal *WebPortal) string {
	// High risk factors
	if portal.IsDevicePortal && portal.IsAdminPortal {
		return "HIGH" // Device admin portals are high risk
	}

	if portal.IsAdminPortal && len(portal.AdminPaths) > 0 {
		return "HIGH" // Admin portals with accessible paths
	}

	if portal.IsDevicePortal {
		return "MEDIUM" // Device portals are generally medium risk
	}

	if portal.IsAdminPortal {
		return "MEDIUM" // Admin portals are medium risk
	}

	if portal.IsDefaultPage {
		return "LOW" // Default pages are lower risk but still notable
	}

	return "LOW"
}

// calculateRiskScore calculates overall risk based on web portal findings
func (m *WebPortalDiscoveryModule) calculateRiskScore(result *WebDiscoveryResult) float64 {
	if len(result.WebPortals) == 0 {
		return 5.0 // Very low risk if no web portals found
	}

	// Calculate risk based on portal types
	baseRisk := float64(len(result.WebPortals)) * 5 // Base risk for web exposure
	deviceRisk := float64(result.DevicePortals) * 25 // High risk for device portals
	adminRisk := float64(result.AdminPortals) * 20 // High risk for admin portals
	defaultRisk := float64(result.DefaultPages) * 10 // Medium risk for default pages

	totalRisk := baseRisk + deviceRisk + adminRisk + defaultRisk

	// Normalize to 0-100 scale
	if totalRisk > 100 {
		totalRisk = 100
	}

	return totalRisk
}

// generateSummary creates human-readable summary
func (m *WebPortalDiscoveryModule) generateSummary(result *WebDiscoveryResult) string {
	if len(result.WebPortals) == 0 {
		return "No web portals or admin interfaces discovered on the local network"
	}

	summary := fmt.Sprintf("Discovered %d web portals across %d hosts",
		len(result.WebPortals), len(result.HostsWithWeb))

	if result.DevicePortals > 0 {
		summary += fmt.Sprintf(", including %d device management portals", result.DevicePortals)
	}

	if result.AdminPortals > 0 {
		summary += fmt.Sprintf(" and %d admin interfaces", result.AdminPortals)
	}

	if result.HighRiskPortals > 0 {
		summary += fmt.Sprintf(" with %d high-risk portals requiring immediate attention", result.HighRiskPortals)
	}

	return summary
}

// generateRecommendations creates actionable recommendations
func (m *WebPortalDiscoveryModule) generateRecommendations(result *WebDiscoveryResult) []string {
	recommendations := []string{}

	if result.DevicePortals > 0 {
		recommendations = append(recommendations,
			"Change default passwords on all discovered device portals",
			"Place device management interfaces behind a management VLAN",
			"Enable HTTPS and disable HTTP for device management",
			"Regularly update firmware on network devices")
	}

	if result.AdminPortals > 0 {
		recommendations = append(recommendations,
			"Implement strong authentication for admin interfaces",
			"Enable multi-factor authentication where possible",
			"Restrict admin interface access to management networks only",
			"Monitor admin interface access logs for suspicious activity")
	}

	if result.DefaultPages > 0 {
		recommendations = append(recommendations,
			"Replace default web pages with custom content or disable web servers",
			"Remove unnecessary web services from production systems")
	}

	if len(result.WebPortals) > 0 {
		recommendations = append(recommendations,
			"Regularly audit web-accessible services and interfaces",
			"Implement web application firewalls for critical interfaces",
			"Use network segmentation to isolate management interfaces",
			"Conduct regular penetration testing of web interfaces")
	}

	return recommendations
}

// Plugin constructor for auto-registration
func NewWebPortalDiscoveryModulePlugin(logger *logger.Logger) modules.ModulePlugin {
	return NewWebPortalDiscoveryModule(logger)
}

// Auto-registration via init() function
func init() {
	modules.RegisterPluginConstructor("WEB_PORTAL_DISCOVERY", NewWebPortalDiscoveryModulePlugin)
}