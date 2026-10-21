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

	// Build naabu args
	naabuArgs := []string{"-list", hostFile.Name(), "-rate", fmt.Sprintf("%d", opts.Rate),
		"-timeout", fmt.Sprintf("%d", opts.TimeoutMs), "-json", "-silent", "-scan-type", opts.ScanType}
	switch opts.PortScope {
	case "top100":
		naabuArgs = append(naabuArgs, "-top-ports", "100")
	case "top1000":
		naabuArgs = append(naabuArgs, "-top-ports", "1000")
	case "custom":
		naabuArgs = append(naabuArgs, "-p", opts.CustomPorts)
	case "all", "default":
		naabuArgs = append(naabuArgs, "-top-ports", "full")
	}

	// Run naabu
	slog.Debug("[sm] discovery: running naabu", "args", strings.Join(naabuArgs, " "))
	naabuCmd := exec.CommandContext(ctx, opts.NaabuPath, naabuArgs...)
	naabuOut, err := naabuCmd.Output()
	if err != nil {
		// naabu may return exit code 1 even on partial success, check if we have output
		if len(naabuOut) == 0 {
			return nil, fmt.Errorf("naabu failed: %w", err)
		}
		slog.Debug("[sm] discovery: naabu returned error but has output", "err", err)
	}
	slog.Debug("[sm] discovery: naabu completed", "output_bytes", len(naabuOut))

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
