package network

import (
	"fmt"
	"net"
	"strings"
)

// ParseSubnetOption converts the subnet option into a flat list of IPv4
// addresses. It accepts CIDR notation, comma separated strings, or arrays.
func ParseSubnetOption(value interface{}) ([]string, error) {
	switch v := value.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return nil, fmt.Errorf("subnet option empty")
		}
		if strings.Contains(trimmed, "/") {
			return expandCIDR(trimmed)
		}
		items := strings.Split(trimmed, ",")
		var ips []string
		for _, item := range items {
			candidate := strings.TrimSpace(item)
			if candidate == "" {
				continue
			}
			if net.ParseIP(candidate) == nil {
				return nil, fmt.Errorf("invalid IP address: %s", candidate)
			}
			ips = append(ips, candidate)
		}
		return ips, nil
	case []interface{}:
		var ips []string
		for _, item := range v {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("invalid subnet entry type %T", item)
			}
			parsed, err := ParseSubnetOption(str)
			if err != nil {
				return nil, err
			}
			ips = append(ips, parsed...)
		}
		return ips, nil
	default:
		return nil, fmt.Errorf("unsupported subnet option type %T", value)
	}
}

func expandCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
	}

	var ips []string
	ones, bits := ipNet.Mask.Size()
	includeAll := bits != 32 || ones == 32

	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		if !includeAll {
			// Skip network and broadcast addresses for IPv4 ranges larger than /32.
			if ipCopy.Equal(ipNet.IP) || isBroadcast(ipCopy, ipNet) {
				continue
			}
		}
		ips = append(ips, ipCopy.String())
		if len(ips) > 256 {
			return nil, fmt.Errorf("CIDR expansion exceeds 256 hosts: %s", cidr)
		}
	}

	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func isBroadcast(ip net.IP, subnet *net.IPNet) bool {
	if ip.To4() == nil {
		return false
	}
	broadcast := make(net.IP, len(subnet.IP))
	copy(broadcast, subnet.IP)
	for i := range broadcast {
		broadcast[i] |= ^subnet.Mask[i]
	}
	return ip.Equal(broadcast)
}
