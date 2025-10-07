package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"decian-agent/internal/logger"
)

// ProbeMethod represents a network discovery technique.
type ProbeMethod string

const (
	// ProbeARP issues an ARP lookup for the target IP.
	ProbeARP ProbeMethod = "ARP"
	// ProbeTCP opens a TCP connection to a well-known port to test reachability.
	ProbeTCP ProbeMethod = "TCP"
	// ProbeICMP sends an ICMP echo request via the system ping utility.
	ProbeICMP ProbeMethod = "ICMP"

	defaultDiscoveryConcurrency = 16
	defaultPerHostTimeout       = 2 * time.Second
)

// DiscoveryOverrides describes caller supplied tweaks to discovery behaviour.
type DiscoveryOverrides struct {
	Methods          []ProbeMethod
	Concurrency      int
	PerHostTimeout   time.Duration
	TCPPorts         []int
	cacheKeyOverride string
}

// TargetHost captures metadata for a responsive IP address.
type TargetHost struct {
	IP          string
	RespondedBy []ProbeMethod
}

// DiscoveryResult summarises discovery across a subnet expansion.
type DiscoveryResult struct {
	Active       []TargetHost
	Unresponsive []string
	Attempted    []string
}

// Discoverer performs network discovery with simple in-memory caching.
type Discoverer struct {
	log   *logger.Logger
	cache map[string]DiscoveryResult
	mu    sync.Mutex
}

// NewDiscoverer creates a discovery helper.
func NewDiscoverer(log *logger.Logger) *Discoverer {
	return &Discoverer{
		log:   log,
		cache: map[string]DiscoveryResult{},
	}
}

// Discover expands the provided targets, probes each IP using the configured
// methods, and caches the resulting set of responsive hosts.
func (d *Discoverer) Discover(targets []string, overrides DiscoveryOverrides) (DiscoveryResult, error) {
	if len(targets) == 0 {
		return DiscoveryResult{}, errors.New("no discovery targets supplied")
	}
	if len(targets) > 256 {
		return DiscoveryResult{}, fmt.Errorf("subnet expansion exceeds 256 hosts: %d", len(targets))
	}

	normalized := normalizeTargets(targets)
	overrides = normalizeOverrides(overrides)
	cacheKey := buildCacheKey(normalized, overrides)

	d.mu.Lock()
	cached, ok := d.cache[cacheKey]
	d.mu.Unlock()
	if ok {
		d.log.Debug("Using cached discovery results", map[string]interface{}{"targets": len(normalized)})
		return cached, nil
	}

	workerCount := overrides.Concurrency
	if workerCount <= 0 {
		workerCount = defaultDiscoveryConcurrency
	}
	if workerCount > len(normalized) {
		workerCount = len(normalized)
	}

	result := DiscoveryResult{Attempted: append([]string{}, normalized...)}

	jobs := make(chan string)
	resultsCh := make(chan TargetHost)
	inactiveCh := make(chan string)

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				respondedBy := d.probeHost(ip, overrides)
				if len(respondedBy) > 0 {
					resultsCh <- TargetHost{IP: ip, RespondedBy: respondedBy}
				} else {
					inactiveCh <- ip
				}
			}
		}()
	}

	go func() {
		for _, ip := range normalized {
			jobs <- ip
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(resultsCh)
		close(inactiveCh)
	}()

	// Read from both channels concurrently to avoid deadlock
	for {
		select {
		case host, ok := <-resultsCh:
			if !ok {
				resultsCh = nil
			} else {
				result.Active = append(result.Active, host)
			}
		case ip, ok := <-inactiveCh:
			if !ok {
				inactiveCh = nil
			} else {
				result.Unresponsive = append(result.Unresponsive, ip)
			}
		}
		// Exit when both channels are closed
		if resultsCh == nil && inactiveCh == nil {
			break
		}
	}

	sort.Slice(result.Active, func(i, j int) bool { return result.Active[i].IP < result.Active[j].IP })
	sort.Strings(result.Unresponsive)

	d.mu.Lock()
	d.cache[cacheKey] = result
	d.mu.Unlock()

	d.log.Info("Completed subnet discovery", map[string]interface{}{
		"total":        len(normalized),
		"responsive":   len(result.Active),
		"unresponsive": len(result.Unresponsive),
	})

	return result, nil
}

func (d *Discoverer) probeHost(ip string, overrides DiscoveryOverrides) []ProbeMethod {
	var respondedBy []ProbeMethod
	for _, method := range overrides.Methods {
		switch method {
		case ProbeARP:
			if probeARP(ip, overrides.PerHostTimeout) {
				respondedBy = append(respondedBy, ProbeARP)
				return respondedBy
			}
		case ProbeTCP:
			if probeTCP(ip, overrides.TCPPorts, overrides.PerHostTimeout) {
				respondedBy = append(respondedBy, ProbeTCP)
				return respondedBy
			}
		case ProbeICMP:
			if probeICMP(ip, overrides.PerHostTimeout) {
				respondedBy = append(respondedBy, ProbeICMP)
				return respondedBy
			}
		}
	}
	return respondedBy
}

func normalizeTargets(targets []string) []string {
	seen := map[string]struct{}{}
	cleaned := make([]string, 0, len(targets))
	for _, t := range targets {
		trimmed := strings.TrimSpace(strings.ToLower(t))
		if trimmed == "" {
			continue
		}
		if _, err := net.ResolveIPAddr("ip", trimmed); err != nil {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		cleaned = append(cleaned, trimmed)
	}
	sort.Strings(cleaned)
	return cleaned
}

func normalizeOverrides(overrides DiscoveryOverrides) DiscoveryOverrides {
	if overrides.PerHostTimeout <= 0 {
		overrides.PerHostTimeout = defaultPerHostTimeout
	}
	if len(overrides.Methods) == 0 {
		overrides.Methods = []ProbeMethod{ProbeARP, ProbeTCP, ProbeICMP}
	}
	if len(overrides.TCPPorts) == 0 {
		overrides.TCPPorts = []int{445, 3389, 80, 443}
	}
	return overrides
}

func buildCacheKey(targets []string, overrides DiscoveryOverrides) string {
	keyParts := []string{
		strings.Join(targets, ","),
		fmt.Sprintf("c%d", overrides.Concurrency),
		fmt.Sprintf("t%d", overrides.PerHostTimeout.Milliseconds()),
	}
	methods := make([]string, 0, len(overrides.Methods))
	for _, m := range overrides.Methods {
		methods = append(methods, string(m))
	}
	keyParts = append(keyParts, strings.Join(methods, "|"))

	ports := make([]string, 0, len(overrides.TCPPorts))
	for _, p := range overrides.TCPPorts {
		ports = append(ports, fmt.Sprintf("%d", p))
	}
	keyParts = append(keyParts, strings.Join(ports, "+"))

	if overrides.cacheKeyOverride != "" {
		keyParts = append(keyParts, overrides.cacheKeyOverride)
	}
	return strings.Join(keyParts, "::")
}

func probeARP(ip string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// On Windows, use ping with minimal timeout to trigger ARP resolution
		// This actively sends an ARP request rather than checking cache
		timeoutMs := int(timeout.Milliseconds())
		if timeoutMs < 100 {
			timeoutMs = 100 // Minimum viable timeout
		}
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", fmt.Sprintf("%d", timeoutMs), ip)
	} else {
		// On Unix systems, use arping for dedicated ARP scanning
		cmd = exec.CommandContext(ctx, "arping", "-c", "1", "-W", fmt.Sprintf("%d", int(timeout.Seconds())), ip)
	}

	// The command success indicates the host responded to ARP/ping
	return cmd.Run() == nil
}

func probeTCP(ip string, ports []int, timeout time.Duration) bool {
	deadline := timeout
	if deadline <= 0 {
		deadline = defaultPerHostTimeout
	}

	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", addr, deadline)
		if err == nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}

func probeICMP(ip string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", fmt.Sprintf("%d", int(timeout.Milliseconds())), ip)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", fmt.Sprintf("%d", int(timeout.Seconds())), ip)
	}

	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}
