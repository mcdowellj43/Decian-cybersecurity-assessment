package modules

import (
	"decian-agent/internal/logger"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// OpenServicePortIDModule implements open service and port identification assessment
type OpenServicePortIDModule struct {
	logger *logger.Logger
	TargetAware
}

// NewOpenServicePortIDModule creates a new open service port identification module
func NewOpenServicePortIDModule(logger *logger.Logger) Module {
	return &OpenServicePortIDModule{
		logger: logger,
	}
}

// Info returns information about the module
func (m *OpenServicePortIDModule) Info() ModuleInfo {
	return ModuleInfo{
		Name:             "Open Service/Port Identification",
		Description:      "Identify listening services, open ports, and network service configurations that may present security risks",
		CheckType:        CheckTypeOpenServicePortID,
		Platform:         "windows",
		DefaultRiskLevel: RiskLevelMedium,
		RequiresAdmin:    false,
	}
}

// Validate checks if the module can run in the current environment
func (m *OpenServicePortIDModule) Validate() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("this module only runs on Windows")
	}
	return nil
}

// Execute runs the open service port identification assessment
func (m *OpenServicePortIDModule) Execute() (*AssessmentResult, error) {
	m.logger.Info("Starting open service port identification assessment")

	result := &AssessmentResult{
		CheckType: CheckTypeOpenServicePortID,
		Data:      make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	var findings []map[string]interface{}
	riskScore := 0.0

	// Check listening ports
	portFindings, portRisk := m.checkListeningPorts()
	if len(portFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Listening Ports",
			"findings": portFindings,
		})
		riskScore += portRisk
	}

	// Check running services
	serviceFindings, serviceRisk := m.checkRunningServices()
	if len(serviceFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Running Services",
			"findings": serviceFindings,
		})
		riskScore += serviceRisk
	}

	// Check network service configurations
	networkServiceFindings, networkServiceRisk := m.checkNetworkServiceConfigurations()
	if len(networkServiceFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Network Service Configurations",
			"findings": networkServiceFindings,
		})
		riskScore += networkServiceRisk
	}

	// Check Windows built-in services
	builtinFindings, builtinRisk := m.checkWindowsBuiltinServices()
	if len(builtinFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Windows Built-in Services",
			"findings": builtinFindings,
		})
		riskScore += builtinRisk
	}

	// Check third-party services
	thirdPartyFindings, thirdPartyRisk := m.checkThirdPartyServices()
	if len(thirdPartyFindings) > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Third-Party Services",
			"findings": thirdPartyFindings,
		})
		riskScore += thirdPartyRisk
	}

	// Cap risk score at 100
	if riskScore > 100 {
		riskScore = 100
	}

	result.Data["findings"] = findings
	result.Data["total_issues"] = len(findings)
	result.RiskScore = riskScore
	result.RiskLevel = DetermineRiskLevel(riskScore)

	m.logger.Info("Open service port identification assessment completed", map[string]interface{}{
		"findings_count": len(findings),
		"risk_score":     riskScore,
		"risk_level":     result.RiskLevel,
	})

	return result, nil
}

// checkListeningPorts scans for listening ports on the system
func (m *OpenServicePortIDModule) checkListeningPorts() ([]string, float64) {
	var findings []string
	var risk float64

	// Common risky ports to check
	riskyPorts := map[int]struct {
		name string
		risk float64
	}{
		21:   {"FTP", 15.0},
		22:   {"SSH", 8.0},
		23:   {"Telnet", 25.0},
		25:   {"SMTP", 10.0},
		53:   {"DNS", 5.0},
		80:   {"HTTP", 8.0},
		110:  {"POP3", 12.0},
		135:  {"RPC Endpoint Mapper", 15.0},
		139:  {"NetBIOS Session", 20.0},
		143:  {"IMAP", 10.0},
		443:  {"HTTPS", 5.0},
		445:  {"SMB", 18.0},
		993:  {"IMAPS", 8.0},
		995:  {"POP3S", 8.0},
		1433: {"SQL Server", 20.0},
		1521: {"Oracle", 18.0},
		3306: {"MySQL", 15.0},
		3389: {"RDP", 15.0},
		5432: {"PostgreSQL", 15.0},
		5900: {"VNC", 20.0},
		8080: {"HTTP Alternate", 10.0},
	}

	// Scan common ports
	listeningPorts := 0
	highRiskPorts := 0

	for port, info := range riskyPorts {
		if m.isPortListening(port) {
			listeningPorts++
			findings = append(findings, fmt.Sprintf("Port %d (%s) is listening", port, info.name))
			risk += info.risk

			// High risk ports
			if info.risk >= 15.0 {
				highRiskPorts++
			}
		}
	}

	if highRiskPorts > 3 {
		findings = append(findings, fmt.Sprintf("High number of risky ports listening: %d", highRiskPorts))
		risk += 15.0
	}

	findings = append(findings, fmt.Sprintf("Total listening ports detected: %d", listeningPorts))

	return findings, risk
}

// isPortListening checks if a specific port is listening
func (m *OpenServicePortIDModule) isPortListening(port int) bool {
	// Try both TCP and UDP
	tcpAddr := fmt.Sprintf(":%d", port)
	if conn, err := net.DialTimeout("tcp", tcpAddr, 1*time.Second); err == nil {
		conn.Close()
		return true
	}

	// Check if we can bind to the port (if it's already in use, binding will fail)
	if listener, err := net.Listen("tcp", tcpAddr); err == nil {
		listener.Close()
		return false // Port was available, so nothing was listening
	}

	return true // Port binding failed, likely something is listening
}

// checkRunningServices analyzes running services for security risks
func (m *OpenServicePortIDModule) checkRunningServices() ([]string, float64) {
	var findings []string
	var risk float64

	// Check services in registry
	servicesKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Services`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return findings, risk
	}
	defer servicesKey.Close()

	serviceNames, err := servicesKey.ReadSubKeyNames(-1)
	if err != nil {
		return findings, risk
	}

	runningServices := 0
	riskyServices := 0
	autoStartServices := 0

	// Services that may present security risks
	riskyServiceNames := []string{
		"telnet", "ftp", "tftp", "snmp", "rsh", "rexec", "finger",
		"iis", "apache", "nginx", "mysql", "postgresql", "oracle",
		"vnc", "teamviewer", "anydesk", "logmein", "radmin",
	}

	for _, serviceName := range serviceNames {
		serviceKey, err := registry.OpenKey(servicesKey, serviceName, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		// Check service start type
		start, _, err := serviceKey.GetIntegerValue("Start")
		if err == nil {
			switch start {
			case 2: // Automatic
				autoStartServices++
				// Check if this is a risky auto-start service
				lowerName := strings.ToLower(serviceName)
				for _, riskyName := range riskyServiceNames {
					if strings.Contains(lowerName, riskyName) {
						findings = append(findings, fmt.Sprintf("Risky auto-start service: %s", serviceName))
						riskyServices++
						risk += 12.0
						break
					}
				}
			case 3: // Manual
				// Check if it's currently running (simplified check)
				runningServices++
			case 4: // Disabled
				// Disabled services are generally good
			}
		}

		// Check service type for network services
		serviceType, _, err := serviceKey.GetIntegerValue("Type")
		if err == nil && (serviceType&0x20) != 0 { // SERVICE_WIN32_SHARE_PROCESS or similar
			// This indicates a service that might accept network connections
			lowerName := strings.ToLower(serviceName)
			for _, riskyName := range riskyServiceNames {
				if strings.Contains(lowerName, riskyName) {
					findings = append(findings, fmt.Sprintf("Network-capable risky service: %s", serviceName))
					risk += 10.0
					break
				}
			}
		}

		serviceKey.Close()
	}

	if autoStartServices > 50 {
		findings = append(findings, fmt.Sprintf("High number of auto-start services: %d", autoStartServices))
		risk += 10.0
	}

	if riskyServices > 0 {
		findings = append(findings, fmt.Sprintf("Risky services detected: %d", riskyServices))
	}

	findings = append(findings, fmt.Sprintf("Total services configured: %d", len(serviceNames)))

	return findings, risk
}

// checkNetworkServiceConfigurations analyzes network service configurations
func (m *OpenServicePortIDModule) checkNetworkServiceConfigurations() ([]string, float64) {
	var findings []string
	var risk float64

	// Check IIS configuration
	iisKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\InetStp`, registry.QUERY_VALUE)
	if err == nil {
		defer iisKey.Close()

		majorVersion, _, err := iisKey.GetIntegerValue("MajorVersion")
		if err == nil {
			findings = append(findings, fmt.Sprintf("IIS detected (version %d)", majorVersion))
			risk += 15.0

			// Check if IIS is running on default port
			findings = append(findings, "IIS web server detected - check for secure configuration")
		}
	}

	// Check SQL Server configuration
	sqlKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Microsoft SQL Server`, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		defer sqlKey.Close()

		instances, err := sqlKey.ReadSubKeyNames(-1)
		if err == nil && len(instances) > 0 {
			findings = append(findings, fmt.Sprintf("SQL Server instances detected: %d", len(instances)))
			risk += 18.0

			// Check for specific SQL Server network protocols
			for _, instance := range instances {
				networkLibKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
					fmt.Sprintf(`SOFTWARE\\Microsoft\\Microsoft SQL Server\\%s\\MSSQLServer\\SuperSocketNetLib`, instance), registry.QUERY_VALUE)
				if err == nil {
					defer networkLibKey.Close()

					tcpEnabled, _, err := networkLibKey.GetIntegerValue("Enabled")
					if err == nil && tcpEnabled == 1 {
						findings = append(findings, fmt.Sprintf("SQL Server instance '%s' has TCP/IP enabled", instance))
						risk += 8.0
					}
				}
			}
		}
	}

	// Check Terminal Services (RDP)
	terminalServicesKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Control\\Terminal Server`, registry.QUERY_VALUE)
	if err == nil {
		defer terminalServicesKey.Close()

		fDenyTSConnections, _, err := terminalServicesKey.GetIntegerValue("fDenyTSConnections")
		if err == nil && fDenyTSConnections == 0 {
			findings = append(findings, "Terminal Services (RDP) is enabled")
			risk += 15.0

			// Check RDP port
			rdpPortKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
				`SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\Tds\\tcp`, registry.QUERY_VALUE)
			if err == nil {
				defer rdpPortKey.Close()

				portNumber, _, err := rdpPortKey.GetIntegerValue("PortNumber")
				if err == nil {
					if portNumber == 3389 {
						findings = append(findings, "RDP is using default port 3389")
						risk += 8.0
					} else {
						findings = append(findings, fmt.Sprintf("RDP is using custom port %d", portNumber))
						risk += 3.0 // Custom port is slightly better but still risky
					}
				}
			}
		}
	}

	return findings, risk
}

// checkWindowsBuiltinServices analyzes Windows built-in services for security risks
func (m *OpenServicePortIDModule) checkWindowsBuiltinServices() ([]string, float64) {
	var findings []string
	var risk float64

	// Check specific Windows services that can present security risks
	riskyWindowsServices := map[string]struct {
		displayName string
		riskLevel   float64
	}{
		"TlntSvr":        {"Telnet", 30.0},
		"MSFTPSVC":       {"FTP Server", 20.0},
		"W3SVC":          {"World Wide Web Publishing", 15.0},
		"SMTPSVC":        {"Simple Mail Transport Protocol", 15.0},
		"SNMP":           {"SNMP Service", 18.0},
		"Browser":        {"Computer Browser", 10.0},
		"RemoteRegistry": {"Remote Registry", 22.0},
		"LanmanServer":   {"Server", 12.0},
		"Spooler":        {"Print Spooler", 8.0},
		"IISADMIN":       {"IIS Admin", 15.0},
	}

	for serviceName, info := range riskyWindowsServices {
		serviceKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			fmt.Sprintf(`SYSTEM\\CurrentControlSet\\Services\\%s`, serviceName), registry.QUERY_VALUE)
		if err == nil {
			defer serviceKey.Close()

			// Check if service exists and is not disabled
			start, _, err := serviceKey.GetIntegerValue("Start")
			if err == nil && start != 4 { // Not disabled
				findings = append(findings, fmt.Sprintf("Risky Windows service enabled: %s (%s)", serviceName, info.displayName))

				if start == 2 { // Auto-start
					risk += info.riskLevel
				} else { // Manual start
					risk += info.riskLevel * 0.5
				}
			}
		}
	}

	// Check Windows features that enable network services
	featuresKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OptionalFeatures`, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		defer featuresKey.Close()

		features, err := featuresKey.ReadSubKeyNames(-1)
		if err == nil {
			riskyFeatures := []string{
				"TelnetClient", "TelnetServer", "TFTP", "SimpleTCP",
				"IIS-WebServer", "IIS-FTPServer",
			}

			for _, feature := range features {
				for _, riskyFeature := range riskyFeatures {
					if strings.Contains(strings.ToLower(feature), strings.ToLower(riskyFeature)) {
						findings = append(findings, fmt.Sprintf("Risky Windows feature detected: %s", feature))
						risk += 12.0
					}
				}
			}
		}
	}

	return findings, risk
}

// checkThirdPartyServices analyzes third-party services for security considerations
func (m *OpenServicePortIDModule) checkThirdPartyServices() ([]string, float64) {
	var findings []string
	var risk float64

	servicesKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\\CurrentControlSet\\Services`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return findings, risk
	}
	defer servicesKey.Close()

	serviceNames, err := servicesKey.ReadSubKeyNames(-1)
	if err != nil {
		return findings, risk
	}

	// Common third-party services that may present risks
	riskyThirdPartyServices := []string{
		"apache", "nginx", "mysql", "postgresql", "mongodb", "redis",
		"elasticsearch", "kibana", "tomcat", "jboss", "websphere",
		"vnc", "teamviewer", "anydesk", "logmein", "hamachi",
		"utorrent", "bittorrent", "emule", "kazaa",
		"pcanywhere", "radmin", "dameware", "remotelymanaged",
	}

	thirdPartyCount := 0
	riskyThirdPartyCount := 0

	for _, serviceName := range serviceNames {
		serviceKey, err := registry.OpenKey(servicesKey, serviceName, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		// Check if it's likely a third-party service by looking at the image path
		imagePath, _, err := serviceKey.GetStringValue("ImagePath")
		if err == nil {
			lowerPath := strings.ToLower(imagePath)
			lowerServiceName := strings.ToLower(serviceName)

			// Check if it's not in Windows system directories
			if !strings.Contains(lowerPath, "\\windows\\") &&
				!strings.Contains(lowerPath, "\\system32\\") &&
				!strings.Contains(lowerPath, "svchost.exe") {

				thirdPartyCount++

				// Check if it matches risky third-party services
				for _, riskyService := range riskyThirdPartyServices {
					if strings.Contains(lowerServiceName, riskyService) ||
						strings.Contains(lowerPath, riskyService) {

						// Check service start type
						start, _, err := serviceKey.GetIntegerValue("Start")
						if err == nil && start != 4 { // Not disabled
							findings = append(findings, fmt.Sprintf("Risky third-party service: %s", serviceName))
							riskyThirdPartyCount++

							if start == 2 { // Auto-start
								risk += 15.0
							} else {
								risk += 8.0
							}
						}
						break
					}
				}
			}
		}

		serviceKey.Close()
	}

	if thirdPartyCount > 20 {
		findings = append(findings, fmt.Sprintf("High number of third-party services: %d", thirdPartyCount))
		risk += 8.0
	}

	if riskyThirdPartyCount > 0 {
		findings = append(findings, fmt.Sprintf("Risky third-party services detected: %d", riskyThirdPartyCount))
	}

	findings = append(findings, fmt.Sprintf("Third-party services detected: %d", thirdPartyCount))

	return findings, risk
}
