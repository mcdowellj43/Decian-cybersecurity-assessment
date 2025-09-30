package networkbased

import "net"

// IncIP increments an IP address by one
// Used for iterating through IP ranges in network scanning modules
func IncIP(ip net.IP) net.IP {
	n := make(net.IP, len(ip))
	copy(n, ip)
	for i := len(n) - 1; i >= 0; i-- {
		n[i]++
		if n[i] > 0 {
			break
		}
	}
	return n
}