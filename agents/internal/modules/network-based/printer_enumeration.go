package networkbased

import (
	"bytes"
	"crypto/tls"
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"encoding/asn1"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// IoTPrinterEnumerationModule discovers printers/IoT devices via safe SNMP/HTTP/port fingerprints
type IoTPrinterEnumerationModule struct {
	logger *logger.Logger
	info   modules.ModuleInfo
}

// NewIoTPrinterEnumerationModule creates a new instance
func NewIoTPrinterEnumerationModule(logger *logger.Logger) *IoTPrinterEnumerationModule {
	return &IoTPrinterEnumerationModule{
		logger: logger,
		info: modules.ModuleInfo{
			Name:             "Printer / IoT Device Enumeration",
			Description:      "Identifies unmanaged printers and IoT devices using SNMP (public), HTTP headers/pages, and common device ports (9100, 554, 5000, 80/443)",
			CheckType:        "IOT_PRINTER_ENUMERATION",
			Platform:         "windows",
			DefaultRiskLevel: "MEDIUM",
			RequiresAdmin:    false,
			Category:         modules.CategoryNetworkBased,
		},
	}
}

// GetInfo returns module info
func (m *IoTPrinterEnumerationModule) GetInfo() modules.ModuleInfo { return m.info }

// Execute probes common IoT/printer indicators and collects minimal identity strings
func (m *IoTPrinterEnumerationModule) Execute() (*modules.AssessmentResult, error) {
	m.logger.Info("Starting IoT/Printer enumeration", nil)
	start := time.Now()

	targets, err := discoverLocalTargets(120, 20, 30)
	if err != nil {
		return nil, fmt.Errorf("target discovery failed: %w", err)
	}

	findings := []map[string]interface{}{}
	for _, host := range targets {
		// 1) SNMP v2c (public) sysDescr (1.3.6.1.2.1.1.1.0) – minimal, safe
		if sys := snmpGetSysDescr(host, "public", 161, 900*time.Millisecond); sys != "" {
			sev := "MEDIUM"
			issue := "SNMP accessible with default 'public' community"
			if looksLikePrinter(sys) || looksLikeIoT(sys) {
				issue = "Printer/IoT identified via SNMP 'public'"
				sev = "HIGH"
			}
			findings = append(findings, map[string]interface{}{
				"host":        host,
				"port":        161,
				"service":     "SNMP",
				"issue":       issue,
				"severity":    sev,
				"evidence":    sys,
				"remediation": "Remove default SNMP community; restrict SNMP to management VLANs; upgrade firmware; forward logs to SIEM.",
				"timestamp":   time.Now(),
			})
		}

		// 2) Raw printing (tcp/9100) often exposed by printers
		if portOpen(host, 9100, 800*time.Millisecond) {
			findings = append(findings, map[string]interface{}{
				"host":        host,
				"port":        9100,
				"service":     "Raw Printing (JetDirect)",
				"issue":       "Printer-like port 9100 exposed",
				"severity":    "MEDIUM",
				"evidence":    "tcp/9100 reachable",
				"remediation": "Restrict printing ports to management VLANs; disable unused protocols; require authenticated print paths.",
				"timestamp":   time.Now(),
			})
		}

		// 3) RTSP (tcp/554) is common on cameras/NVRs
		if portOpen(host, 554, 800*time.Millisecond) {
			findings = append(findings, map[string]interface{}{
				"host":        host,
				"port":        554,
				"service":     "RTSP",
				"issue":       "Potential camera/NVR endpoint (RTSP) exposed",
				"severity":    "MEDIUM",
				"evidence":    "tcp/554 reachable",
				"remediation": "Segment cameras to a dedicated VLAN; disable external access; update firmware.",
				"timestamp":   time.Now(),
			})
		}

		// 4) HTTP probes for device strings on 80/443/5000
		for _, hp := range []struct {
			port int
			tls  bool
		}{{80, false}, {443, true}, {5000, false}} {
			if !portOpen(host, hp.port, 800*time.Millisecond) {
				continue
			}
			b, hdrs := httpBanner(host, hp.port, hp.tls, 1200*time.Millisecond)
			if b == "" && len(hdrs) == 0 {
				continue
			}
			id := deviceIdentityFromHTTP(b, hdrs)
			if id != "" {
				sev := "MEDIUM"
				if looksLikePrinter(id) || looksLikeIoT(id) {
					sev = "MEDIUM"
				}
				findings = append(findings, map[string]interface{}{
					"host":        host,
					"port":        hp.port,
					"service":     "HTTP",
					"issue":       "IoT/Printer-like HTTP identity observed",
					"severity":    sev,
					"evidence":    id,
					"remediation": "Restrict device portals to management networks; enforce strong creds; remove default passwords; update firmware.",
					"timestamp":   time.Now(),
				})
			}
		}
	}

	score := scoreBySeverity(findings, 15, 8, 0)
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

// Validate basic capability
func (m *IoTPrinterEnumerationModule) Validate() error {
	_, err := net.Interfaces()
	return err
}

// ---------- lightweight probes ----------

func portOpen(host string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		_ = c.Close()
		return true
	}
	return false
}

func httpBanner(host string, port int, tlsOn bool, timeout time.Duration) (string, map[string]string) {
	scheme := "http"
	if tlsOn {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: timeout,
			DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}
	req, _ := http.NewRequest(http.MethodHead, url, nil)
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return "", nil
	}
	defer resp.Body.Close()
	h := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			h[strings.ToLower(k)] = v[0]
		}
	}
	b := fmt.Sprintf("HTTP/%d.%d %d %s", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, strings.TrimSpace(resp.Status))
	if s, ok := h["server"]; ok {
		b = b + " | Server: " + s
	}
	return b, h
}

func deviceIdentityFromHTTP(banner string, hdrs map[string]string) string {
	if s, ok := hdrs["server"]; ok {
		return strings.TrimSpace(s)
	}
	// Look for hints in banner if no Server header
	if strings.Contains(strings.ToLower(banner), "printer") || strings.Contains(strings.ToLower(banner), "jetdirect") {
		return banner
	}
	return ""
}

func looksLikePrinter(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "hp") && strings.Contains(l, "jetdirect") ||
		strings.Contains(l, "xerox") ||
		strings.Contains(l, "ricoh") ||
		strings.Contains(l, "brother") ||
		strings.Contains(l, "kyocera") ||
		strings.Contains(l, "canon")
}

func looksLikeIoT(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "camera") || strings.Contains(l, "nvr") || strings.Contains(l, "dvr") ||
		strings.Contains(l, "tplink") || strings.Contains(l, "hikvision") || strings.Contains(l, "dahua") ||
		strings.Contains(l, "synology") || strings.Contains(l, "qnap")
}

// -------- minimal SNMP v2c sysDescr fetch (OID 1.3.6.1.2.1.1.1.0) --------

// snmpGetSysDescr sends a minimal SNMPv2c GET and returns sysDescr if accessible via 'public'
func snmpGetSysDescr(host, community string, port int, timeout time.Duration) string {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	oidSysDescr := asn1.ObjectIdentifier{1, 3, 6, 1, 2, 1, 1, 1, 0}
	// SNMPv2c GET PDU:
	// SEQ { version(1), community(OctetString 'public'), data(GetRequest-PDU) }
	pdu := buildSNMPv2Get(community, oidSysDescr)

	if _, err := conn.Write(pdu); err != nil {
		return ""
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n <= 0 {
		return ""
	}
	return parseSNMPSysDescr(buf[:n])
}

func buildSNMPv2Get(community string, oid asn1.ObjectIdentifier) []byte {
	// Very small encoder using encoding/asn1 for substructures, hand-build outer sequence
	// version = 1 (v2c)
	version, _ := asn1.Marshal(1)
	com, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagOctetString, IsCompound: false, Bytes: []byte(community)})

	// VarBind: SEQ{ OID, NULL }
	oidEnc, _ := asn1.Marshal(oid)
	nullEnc, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagNull, IsCompound: false, Bytes: nil})
	vb := seq(append(oidEnc, nullEnc...))

	// VarBindList: SEQ of vb
	vbl := seq(vb)

	// GetRequest-PDU (ContextSpecific, Constructed, Tag=0)
	reqID, _ := asn1.Marshal(1)   // request-id
	errStat, _ := asn1.Marshal(0) // error-status
	errIdx, _ := asn1.Marshal(0)  // error-index
	getBody := append(append(append(reqID, errStat...), errIdx...), vbl...)
	pdu := taggedSeq(0xa0, getBody)

	// message: SEQ{version, community, pdu}
	msg := seq(append(append(version, com...), pdu...))
	return msg
}

func parseSNMPSysDescr(pkt []byte) string {
	// Very minimal parsing: look for first OCTET STRING after an OID 1.3.6.1.2.1.1.1.0
	// This is NOT a full SNMP parser—just enough for sysDescr in typical responses.
	idx := bytes.Index(pkt, []byte{0x06}) // OID tag
	for idx >= 0 && idx < len(pkt)-2 {
		// naive length read
		l := int(pkt[idx+1])
		if idx+2+l >= len(pkt) {
			break
		}
		oidRaw := pkt[idx+2 : idx+2+l]
		// quick check for sysDescr suffix (.1.3.6.1.2.1.1.1.0 encoded)
		if bytes.Contains(oidRaw, []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}) ||
			bytes.Equal(oidRaw, []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}) {
			// search forward for OCTET STRING (0x04)
			strIdx := bytes.Index(pkt[idx+2+l:], []byte{0x04})
			if strIdx < 0 {
				return ""
			}
			strIdx += idx + 2 + l
			if strIdx+2 > len(pkt) {
				return ""
			}
			ln := int(pkt[strIdx+1])
			if strIdx+2+ln > len(pkt) {
				return ""
			}
			return string(pkt[strIdx+2 : strIdx+2+ln])
		}
		idx = bytes.Index(pkt[idx+2+l:], []byte{0x06})
		if idx >= 0 {
			idx += 2 + l
		}
	}
	return ""
}

// ASN.1 helpers
func seq(inner []byte) []byte                 { return append([]byte{0x30, byte(len(inner))}, inner...) }
func taggedSeq(tag byte, inner []byte) []byte { return append([]byte{tag, byte(len(inner))}, inner...) }

// Plugin constructor (Required)
func NewIoTPrinterEnumerationModulePlugin(logger *logger.Logger) modules.ModulePlugin {
	return NewIoTPrinterEnumerationModule(logger)
}

// Auto-registration (Required)
func init() {
	modules.RegisterPluginConstructor("IOT_PRINTER_ENUMERATION", NewIoTPrinterEnumerationModulePlugin)
}
