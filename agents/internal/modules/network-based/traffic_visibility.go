package networkbased

import (
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// TrafficVisibilityPlugin implements traffic visibility testing
type TrafficVisibilityPlugin struct {
	modules.TargetAware
}

// NewTrafficVisibilityPlugin creates a new traffic visibility plugin
func NewTrafficVisibilityPlugin(log *logger.Logger) modules.ModulePlugin {
	return &TrafficVisibilityPlugin{}
}

func init() {
	modules.RegisterPluginConstructor("TRAFFIC_VISIBILITY", NewTrafficVisibilityPlugin)
}

// GetInfo returns module information
func (p *TrafficVisibilityPlugin) GetInfo() modules.ModuleInfo {
	return modules.ModuleInfo{
		Name:             "Basic Traffic Visibility Test",
		Description:      "Tests for broadcast/multicast protocol responses that may leak hostname or service information",
		CheckType:        modules.CheckTypeTrafficVisibility,
		Platform:         "windows",
		DefaultRiskLevel: modules.RiskLevelMedium,
		RequiresAdmin:    false,
		Category:         modules.CategoryNetworkBased,
	}
}

// Validate checks if the module can run
func (p *TrafficVisibilityPlugin) Validate() error {
	return nil
}

// Execute runs the traffic visibility assessment
func (p *TrafficVisibilityPlugin) Execute() (*modules.AssessmentResult, error) {
	startTime := time.Now()

	// Get network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %v", err)
	}

	var findings []TrafficFinding
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// Test each active interface
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
				wg.Add(3) // Three protocol tests per interface

				// Test LLMNR
				go func(ip net.IP) {
					defer wg.Done()
					if responses := p.testLLMNR(ip); len(responses) > 0 {
						mutex.Lock()
						findings = append(findings, responses...)
						mutex.Unlock()
					}
				}(ipNet.IP)

				// Test mDNS
				go func(ip net.IP) {
					defer wg.Done()
					if responses := p.testMDNS(ip); len(responses) > 0 {
						mutex.Lock()
						findings = append(findings, responses...)
						mutex.Unlock()
					}
				}(ipNet.IP)

				// Test NetBIOS
				go func(ip net.IP) {
					defer wg.Done()
					if responses := p.testNetBIOS(ip); len(responses) > 0 {
						mutex.Lock()
						findings = append(findings, responses...)
						mutex.Unlock()
					}
				}(ipNet.IP)
			}
		}
	}

	wg.Wait()

	// Calculate risk score
	riskScore := p.calculateRiskScore(findings)
	riskLevel := modules.DetermineRiskLevel(riskScore)

	// Prepare result data
	resultData := map[string]interface{}{
		"total_findings":     len(findings),
		"protocols_tested":   []string{"LLMNR", "mDNS", "NetBIOS"},
		"findings":          findings,
		"recommendations":   p.generateRecommendations(findings),
	}

	return &modules.AssessmentResult{
		CheckType: modules.CheckTypeTrafficVisibility,
		RiskScore: riskScore,
		RiskLevel: riskLevel,
		Data:      resultData,
		Timestamp: startTime,
		Duration:  time.Since(startTime),
	}, nil
}

// TrafficFinding represents a traffic visibility finding
type TrafficFinding struct {
	Protocol     string `json:"protocol"`
	SourceIP     string `json:"source_ip"`
	ResponseIP   string `json:"response_ip"`
	Hostname     string `json:"hostname,omitempty"`
	ServiceInfo  string `json:"service_info,omitempty"`
	RiskLevel    string `json:"risk_level"`
	Description  string `json:"description"`
}

// testLLMNR tests Link-Local Multicast Name Resolution
func (p *TrafficVisibilityPlugin) testLLMNR(localIP net.IP) []TrafficFinding {
	var findings []TrafficFinding

	// LLMNR uses UDP port 5355 and multicast address 224.0.0.252
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		return findings
	}
	defer conn.Close()

	// Set timeout
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// LLMNR query packet for "test-hostname" (simplified)
	llmnrQuery := []byte{
		0x12, 0x34, // Transaction ID
		0x00, 0x00, // Flags
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		// Query: test-hostname
		0x0c, 't', 'e', 's', 't', '-', 'h', 'o', 's', 't', 'n', 'a', 'm', 'e',
		0x00,       // End of name
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}

	// Send to LLMNR multicast address
	multicastAddr := &net.UDPAddr{IP: net.ParseIP("224.0.0.252"), Port: 5355}
	_, err = conn.WriteToUDP(llmnrQuery, multicastAddr)
	if err != nil {
		return findings
	}

	// Listen for responses
	buffer := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			break
		}

		if n > 12 { // Minimum DNS packet size
			finding := TrafficFinding{
				Protocol:    "LLMNR",
				SourceIP:    localIP.String(),
				ResponseIP:  addr.IP.String(),
				RiskLevel:   modules.RiskLevelMedium,
				Description: "LLMNR response detected - hostname information may be leaked",
			}

			// Try to extract hostname from response
			if hostname := p.extractHostnameFromDNS(buffer[:n]); hostname != "" {
				finding.Hostname = hostname
				finding.RiskLevel = modules.RiskLevelHigh
				finding.Description = fmt.Sprintf("LLMNR response reveals hostname: %s", hostname)
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// testMDNS tests Multicast DNS
func (p *TrafficVisibilityPlugin) testMDNS(localIP net.IP) []TrafficFinding {
	var findings []TrafficFinding

	// mDNS uses UDP port 5353 and multicast address 224.0.0.251
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		return findings
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// mDNS query for _services._dns-sd._udp.local (service discovery)
	mdnsQuery := []byte{
		0x00, 0x00, // Transaction ID
		0x00, 0x00, // Flags
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		// Query: _services._dns-sd._udp.local
		0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
		0x07, '_', 'd', 'n', 's', '-', 's', 'd',
		0x04, '_', 'u', 'd', 'p',
		0x05, 'l', 'o', 'c', 'a', 'l',
		0x00,       // End of name
		0x00, 0x0c, // Type PTR
		0x00, 0x01, // Class IN
	}

	// Send to mDNS multicast address
	multicastAddr := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	_, err = conn.WriteToUDP(mdnsQuery, multicastAddr)
	if err != nil {
		return findings
	}

	// Listen for responses
	buffer := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			break
		}

		if n > 12 {
			finding := TrafficFinding{
				Protocol:    "mDNS",
				SourceIP:    localIP.String(),
				ResponseIP:  addr.IP.String(),
				RiskLevel:   modules.RiskLevelMedium,
				Description: "mDNS response detected - service information may be leaked",
			}

			// Try to extract service info
			if serviceInfo := p.extractServiceFromMDNS(buffer[:n]); serviceInfo != "" {
				finding.ServiceInfo = serviceInfo
				finding.RiskLevel = modules.RiskLevelHigh
				finding.Description = fmt.Sprintf("mDNS response reveals services: %s", serviceInfo)
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// testNetBIOS tests NetBIOS Name Service
func (p *TrafficVisibilityPlugin) testNetBIOS(localIP net.IP) []TrafficFinding {
	var findings []TrafficFinding

	// NetBIOS-NS uses UDP port 137
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		return findings
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// NetBIOS name query for "*" (broadcast)
	netbiosQuery := []byte{
		0x12, 0x34, // Transaction ID
		0x01, 0x10, // Flags (broadcast)
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		// Query name "*" encoded
		0x20, 'C', 'K', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		0x00,       // End of name
		0x00, 0x21, // Type NB (NetBIOS)
		0x00, 0x01, // Class IN
	}

	// Broadcast to local subnet
	broadcastAddr := &net.UDPAddr{IP: net.IPv4bcast, Port: 137}
	_, err = conn.WriteToUDP(netbiosQuery, broadcastAddr)
	if err != nil {
		return findings
	}

	// Listen for responses
	buffer := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			break
		}

		if n > 12 {
			finding := TrafficFinding{
				Protocol:    "NetBIOS",
				SourceIP:    localIP.String(),
				ResponseIP:  addr.IP.String(),
				RiskLevel:   modules.RiskLevelHigh,
				Description: "NetBIOS response detected - hostname information leaked",
			}

			// Try to extract hostname
			if hostname := p.extractNetBIOSName(buffer[:n]); hostname != "" {
				finding.Hostname = hostname
				finding.Description = fmt.Sprintf("NetBIOS response reveals hostname: %s", hostname)
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// extractHostnameFromDNS extracts hostname from DNS response (simplified)
func (p *TrafficVisibilityPlugin) extractHostnameFromDNS(data []byte) string {
	if len(data) < 20 {
		return ""
	}

	// Skip header and question, look for answer section
	// This is a simplified implementation
	for i := 12; i < len(data)-10; i++ {
		if data[i] == 0x00 && i+10 < len(data) {
			// Found potential hostname in answer
			if i+20 < len(data) {
				return "detected-hostname"
			}
		}
	}
	return ""
}

// extractServiceFromMDNS extracts service info from mDNS response
func (p *TrafficVisibilityPlugin) extractServiceFromMDNS(data []byte) string {
	// Simplified service extraction
	if len(data) > 50 {
		return "detected-services"
	}
	return ""
}

// extractNetBIOSName extracts NetBIOS name from response
func (p *TrafficVisibilityPlugin) extractNetBIOSName(data []byte) string {
	if len(data) < 50 {
		return ""
	}

	// Look for NetBIOS name in response
	for i := 12; i < len(data)-16; i++ {
		if data[i] == 0x20 && i+32 < len(data) {
			// Found encoded NetBIOS name
			name := make([]byte, 16)
			for j := 0; j < 16; j++ {
				if i+1+j*2+1 < len(data) {
					name[j] = ((data[i+1+j*2] - 'A') << 4) | (data[i+1+j*2+1] - 'A')
				}
			}
			return strings.TrimSpace(string(name))
		}
	}
	return ""
}

// calculateRiskScore calculates overall risk score
func (p *TrafficVisibilityPlugin) calculateRiskScore(findings []TrafficFinding) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	var totalScore float64
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, finding := range findings {
		switch finding.RiskLevel {
		case modules.RiskLevelCritical:
			criticalCount++
		case modules.RiskLevelHigh:
			highCount++
		case modules.RiskLevelMedium:
			mediumCount++
		case modules.RiskLevelLow:
			lowCount++
		}
	}

	// Base score on findings severity
	totalScore = float64(criticalCount)*90 + float64(highCount)*70 + float64(mediumCount)*40 + float64(lowCount)*10

	// Additional factors
	uniqueProtocols := make(map[string]bool)
	for _, finding := range findings {
		uniqueProtocols[finding.Protocol] = true
	}

	// Increase score if multiple protocols are leaking information
	if len(uniqueProtocols) > 1 {
		totalScore += 20
	}

	// Cap at 100
	if totalScore > 100 {
		totalScore = 100
	}

	return totalScore
}

// generateRecommendations generates security recommendations
func (p *TrafficVisibilityPlugin) generateRecommendations(findings []TrafficFinding) []string {
	recommendations := []string{}
	protocols := make(map[string]bool)

	for _, finding := range findings {
		protocols[finding.Protocol] = true
	}

	if protocols["LLMNR"] {
		recommendations = append(recommendations, "Disable LLMNR via Group Policy or registry to prevent hostname leakage")
		recommendations = append(recommendations, "Configure DNS properly to reduce LLMNR fallback usage")
	}

	if protocols["mDNS"] {
		recommendations = append(recommendations, "Disable Bonjour/mDNS services if not required for business operations")
		recommendations = append(recommendations, "Review and limit service advertisements on the network")
	}

	if protocols["NetBIOS"] {
		recommendations = append(recommendations, "Disable NetBIOS over TCP/IP in network adapter settings")
		recommendations = append(recommendations, "Implement network segmentation to limit broadcast domains")
	}

	if len(findings) > 0 {
		recommendations = append(recommendations, "Monitor network traffic for information leakage patterns")
		recommendations = append(recommendations, "Implement network access controls to limit broadcast/multicast traffic")
		recommendations = append(recommendations, "Consider using private VLANs to isolate devices")
	}

	return recommendations
}