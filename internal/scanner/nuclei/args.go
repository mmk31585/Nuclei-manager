package nuclei

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Options is the fully validated, already-resolved input for one nuclei run.
type Options struct {
	TargetsFile   string   // absolute path
	ExcludeHosts  []string // hosts, IPs or CIDRs
	TemplatePaths []string // absolute directories
	TemplateIDs   []string
	Tags          []string
	ExcludeTags   []string
	Severities    []string
	Protocols     []string
	RateLimit     int
	Concurrency   int
	BulkSize      int
	TimeoutSec    int
	Retries       int
	MaxHostError  int
	OAST          bool
}

var (
	reTag  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	reID   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.*-]{0,127}$`)
	reHost = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,254}$`)
)

var allowedSeverity = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}

// code and headless can run commands or drive a browser; file reads local files. Never allowed.
var allowedProtocol = map[string]bool{
	"dns": true, "http": true, "tcp": true, "ssl": true,
	"websocket": true, "whois": true, "javascript": true, "workflow": true,
}

// forbiddenFlags are nuclei flags the service must never pass, even indirectly.
var forbiddenFlags = []string{
	"-code", "-headless", "-dast", "-fuzz", "-lfa", "-allow-local-file-access",
	"-env-vars", "-update-templates", "-update", "-reset", "-sandbox",
}

func addList(args []string, flag string, vals []string, ok func(string) bool) ([]string, error) {
	if len(vals) == 0 {
		return args, nil
	}
	for _, v := range vals {
		if !ok(v) {
			return nil, fmt.Errorf("invalid value %q for %s", v, flag)
		}
	}
	return append(args, flag, strings.Join(vals, ",")), nil
}

func BuildArgs(o Options) ([]string, error) {
	if !filepath.IsAbs(o.TargetsFile) {
		return nil, errors.New("targets file must be an absolute path")
	}
	args := []string{
		"-list", o.TargetsFile,
		"-jsonl", "-no-color", "-disable-update-check",
		"-stats", "-stats-interval", "15",
	}
	numbers := []struct {
		name     string
		v        int
		min, max int
	}{
		{"rate-limit", o.RateLimit, 1, 10000},
		{"concurrency", o.Concurrency, 1, 500},
		{"bulk-size", o.BulkSize, 1, 500},
		{"timeout", o.TimeoutSec, 1, 300},
		{"retries", o.Retries, 0, 10},
		{"max-host-error", o.MaxHostError, 1, 1000},
	}
	for _, n := range numbers {
		if n.v < n.min || n.v > n.max {
			return nil, fmt.Errorf("%s must be between %d and %d", n.name, n.min, n.max)
		}
		args = append(args, "-"+n.name, strconv.Itoa(n.v))
	}
	if !o.OAST {
		args = append(args, "-no-interactsh")
	}

	var err error
	lists := []struct {
		flag string
		vals []string
		ok   func(string) bool
	}{
		{"-exclude-hosts", o.ExcludeHosts, reHost.MatchString},
		{"-templates", o.TemplatePaths, func(p string) bool {
			return filepath.IsAbs(p) && !strings.ContainsAny(p, ",\r\n")
		}},
		{"-template-id", o.TemplateIDs, reID.MatchString},
		{"-tags", o.Tags, reTag.MatchString},
		{"-exclude-tags", o.ExcludeTags, reTag.MatchString},
		{"-severity", o.Severities, func(s string) bool { return allowedSeverity[s] }},
		{"-type", o.Protocols, func(s string) bool { return allowedProtocol[s] }},
	}
	for _, l := range lists {
		if args, err = addList(args, l.flag, l.vals, l.ok); err != nil {
			return nil, err
		}
	}

	// Defense in depth: none of the forbidden flags may ever appear.
	joined := strings.Join(args, " ")
	for _, f := range forbiddenFlags {
		if strings.Contains(joined, f+" ") || strings.HasSuffix(joined, f) {
			return nil, fmt.Errorf("forbidden nuclei flag %s", f)
		}
	}
	return args, nil
}
