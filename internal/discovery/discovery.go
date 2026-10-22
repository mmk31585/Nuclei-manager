package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

// Options configures a discovery run.
type Options struct {
	PortScope   string
	CustomPorts string
	Rate        int
	TimeoutMs   int
	ScanType    string
	NaabuPath   string
	HttpxPath   string
	// ExcludeHosts are hosts, IPs or CIDRs to exclude from naabu scanning.
	ExcludeHosts []string
	// ExcludePorts are ports to exclude from naabu scanning.
	ExcludePorts []string
	// Retries is the number of retries for port scan (default 1 for speed).
	Retries int
	// SkipHostDiscovery skips host discovery (ping/probes) - useful when scanning IPs directly.
	SkipHostDiscovery bool
	// Verify validates open ports with TCP verification for accuracy.
	Verify bool
	// WarmUpTime is the time in seconds between scan phases.
	WarmUpTime int
	// ExcludeCDN skips full port scans for CDN/WAF (only scans 80,443).
	ExcludeCDN bool
}

// Discoverer is the interface for port/service discovery.
type Discoverer interface {
	Discover(ctx context.Context, hosts []string, opts Options) ([]domain.Endpoint, error)
}

// naabuResult represents a naabu JSON output line.
type naabuResult struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// httpxResult represents an httpx JSON output line.
type httpxResult struct {
	URL        string `json:"url"`
	Scheme     string `json:"scheme"`
	Port       string `json:"port"`
	StatusCode int    `json:"status_code"`
	Host       string `json:"host"`
}

// discoverer implements Discoverer.
type discoverer struct{}

// New returns a Discoverer implementation.
func New() Discoverer { return &discoverer{} }
func extractHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Try URL parse
	if strings.Contains(raw, "://") {
		parts := strings.SplitN(raw, "://", 2)
		if len(parts) == 2 {
			host := parts[1]
			// Remove path
			if idx := strings.IndexByte(host, '/'); idx >= 0 {
				host = host[:idx]
			}
			// Remove port
			if idx := strings.LastIndexByte(host, ':'); idx >= 0 {
				host = host[:idx]
			}
			return host
		}
	}
	// Remove path if present
	if idx := strings.IndexByte(raw, '/'); idx >= 0 {
		raw = raw[:idx]
	}
	// Remove port if present (but keep IP)
	if idx := strings.LastIndexByte(raw, ':'); idx >= 0 {
		// Check if it's an IPv6 address
		if !strings.Contains(raw, "]") {
			raw = raw[:idx]
		}
	}
	return raw
}

// isPort returns true when s is a plain numeric port (or comma-separated ports).
func isPort(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// Discover runs naabu then httpx and returns merged endpoints.
func (d *discoverer) Discover(ctx context.Context, hosts []string, opts Options) ([]domain.Endpoint, error) {
	if opts.NaabuPath == "" {
		opts.NaabuPath = "naabu"
	}
	if opts.HttpxPath == "" {
		opts.HttpxPath = "httpx"
	}
	if opts.Rate == 0 {
		opts.Rate = 1000
	}
	if opts.TimeoutMs == 0 {
		opts.TimeoutMs = 1000
	}
	if opts.ScanType == "" {
		opts.ScanType = "c"
	}
	if opts.Retries == 0 {
		opts.Retries = 1 // Default to 1 for faster scans
	}

	// Extract bare hosts from URLs
	var bareHosts []string
	for _, h := range hosts {
		bare := extractHost(h)
		if bare != "" {
			bareHosts = append(bareHosts, bare)
		}
	}
	if len(bareHosts) == 0 {
		return nil, fmt.Errorf("no valid hosts")
	}

	// Write hosts to temp file
	hostFile, err := os.CreateTemp("", "discovery-hosts-*")
	if err != nil {
		return nil, fmt.Errorf("create host file: %w", err)
	}
	defer os.Remove(hostFile.Name())
	for _, h := range bareHosts {
		fmt.Fprintln(hostFile, h)
	}
	hostFile.Close()

	// Build naabu args. -n skips the nmap dependency (not available in the
	// container), -sa uses system DNS resolution for reliability.
	naabuArgs := []string{"-list", hostFile.Name(), "-rate", fmt.Sprintf("%d", opts.Rate),
		"-timeout", fmt.Sprintf("%d", opts.TimeoutMs), "-json", "-silent", "-scan-type", opts.ScanType,
		"-n", "-sa", "-retries", fmt.Sprintf("%d", opts.Retries)}
	if opts.SkipHostDiscovery {
		naabuArgs = append(naabuArgs, "-Pn")
	}
	if opts.Verify {
		naabuArgs = append(naabuArgs, "-verify")
	}
	if opts.WarmUpTime > 0 {
		naabuArgs = append(naabuArgs, "-warm-up-time", fmt.Sprintf("%d", opts.WarmUpTime))
	}
	if opts.ExcludeCDN {
		naabuArgs = append(naabuArgs, "-exclude-cdn")
	}
	switch opts.PortScope {
	case "top100":
		naabuArgs = append(naabuArgs, "-top-ports", "100")
	case "top1000":
		naabuArgs = append(naabuArgs, "-top-ports", "1000")
	case "custom":
		naabuArgs = append(naabuArgs, "-p", opts.CustomPorts)
	case "all":
		// -p - scans all 65535 ports
		naabuArgs = append(naabuArgs, "-p", "-")
	case "default":
		// Default: common web/dev ports
		naabuArgs = append(naabuArgs, "-p", "80,443,8080,8443,3000,8000,5000,3001,5001,9000,9090")
	}

	// Split exclude entries: numeric = ports, everything else = hosts/IPs/CIDRs.
	var excludeHosts, excludePorts []string
	for _, e := range opts.ExcludeHosts {
		if isPort(e) {
			excludePorts = append(excludePorts, e)
		} else {
			excludeHosts = append(excludeHosts, e)
		}
	}
	excludePorts = append(excludePorts, opts.ExcludePorts...)

	if len(excludeHosts) > 0 {
		naabuArgs = append(naabuArgs, "-exclude-hosts", strings.Join(excludeHosts, ","))
	}
	if len(excludePorts) > 0 {
		naabuArgs = append(naabuArgs, "-exclude-ports", strings.Join(excludePorts, ","))
	}

	// Run naabu
	slog.Debug("[sm] discovery: running naabu", "args", strings.Join(naabuArgs, " "))
	naabuCmd := exec.CommandContext(ctx, opts.NaabuPath, naabuArgs...)
	naabuOut, err := naabuCmd.Output()
	if err != nil {
		// naabu may return exit code 1 even on partial success, check if we have output
		if len(naabuOut) == 0 {
			return nil, fmt.Errorf("naabu failed (no output): %w", err)
		}
		slog.Debug("[sm] discovery: naabu returned error but has output", "err", err)
	}
	slog.Debug("[sm] discovery: naabu completed", "output_bytes", len(naabuOut))

	if len(naabuOut) == 0 {
		slog.Warn("[sm] discovery: naabu produced no output at all", "hosts", bareHosts, "port_scope", opts.PortScope)
	}

	// Parse naabu results
	var openPorts []struct {
		Host string
		Port int
	}
	scanner := bufio.NewScanner(strings.NewReader(string(naabuOut)))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var r naabuResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		host := r.Host
		if host == "" {
			host = r.IP
		}
		openPorts = append(openPorts, struct {
			Host string
			Port int
		}{Host: host, Port: r.Port})
	}

	if len(openPorts) == 0 {
		slog.Debug("[sm] discovery: no open ports found")
		return nil, nil
	}
	slog.Debug("[sm] discovery: found open ports", "count", len(openPorts))

	// Write host:port to temp file for httpx
	portFile, err := os.CreateTemp("", "discovery-ports-*")
	if err != nil {
		return nil, fmt.Errorf("create port file: %w", err)
	}
	defer os.Remove(portFile.Name())
	for _, p := range openPorts {
		fmt.Fprintf(portFile, "%s:%d\n", p.Host, p.Port)
	}
	portFile.Close()

	// Run httpx
	slog.Debug("[sm] discovery: running httpx", "hosts", len(openPorts))
	httpxArgs := []string{"-l", portFile.Name(), "-json", "-silent", "-timeout", "10", "-threads", "25"}
	httpxCmd := exec.CommandContext(ctx, opts.HttpxPath, httpxArgs...)
	httpxOut, _ := httpxCmd.Output() // httpx may exit non-zero but still produce output
	slog.Debug("[sm] discovery: httpx completed", "output_bytes", len(httpxOut))

	// Parse httpx results into a map for quick lookup
	webMap := make(map[string]domain.Endpoint)
	httpxScanner := bufio.NewScanner(strings.NewReader(string(httpxOut)))
	httpxScanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for httpxScanner.Scan() {
		line := strings.TrimSpace(httpxScanner.Text())
		if line == "" {
			continue
		}
		var r httpxResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		host := r.Host
		if host == "" {
			// extract host from URL
			host = r.URL
		}
		port, _ := strconv.Atoi(r.Port)
		ep := domain.Endpoint{
			Host:   host,
			Port:   port,
			Scheme: r.Scheme,
			URL:    r.URL,
			IsWeb:  true,
			Source: "httpx",
		}
		key := fmt.Sprintf("%s:%d", host, port)
		webMap[key] = ep
	}

	// Build merged endpoint list
	seen := make(map[string]bool)
	var endpoints []domain.Endpoint
	for _, p := range openPorts {
		key := fmt.Sprintf("%s:%d", p.Host, p.Port)
		if ep, ok := webMap[key]; ok {
			if !seen[key] {
				endpoints = append(endpoints, ep)
				seen[key] = true
			}
		} else {
			if !seen[key] {
				endpoints = append(endpoints, domain.Endpoint{
					Host:   p.Host,
					Port:   p.Port,
					IsWeb:  false,
					Source: "naabu",
				})
				seen[key] = true
			}
		}
	}

	// Sort for stable output
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Host != endpoints[j].Host {
			return endpoints[i].Host < endpoints[j].Host
		}
		return endpoints[i].Port < endpoints[j].Port
	})

	return endpoints, nil
}
