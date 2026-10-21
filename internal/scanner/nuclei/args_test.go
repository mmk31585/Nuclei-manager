package nuclei

import (
	"strings"
	"testing"
)

func TestBuildArgsValid(t *testing.T) {
	o := Options{
		TargetsFile:   "/tmp/targets.txt",
		ExcludeHosts:  []string{"evil.invalid"},
		TemplatePaths: []string{"/opt/nuclei-templates"},
		TemplateIDs:   []string{"cve-2021-0001"},
		Tags:          []string{"cve", "exposure"},
		ExcludeTags:   []string{"dos"},
		Severities:    []string{"medium", "high"},
		Protocols:     []string{"http", "ssl"},
		RateLimit:     50,
		Concurrency:   25,
		BulkSize:      25,
		TimeoutSec:    10,
		Retries:       1,
		MaxHostError:  30,
		NoInteractsh:  true,
	}
	args, err := BuildArgs(o)
	if err != nil {
		t.Fatalf("BuildArgs valid = err %v", err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"-list", "/tmp/targets.txt", "-jsonl", "-no-color",
		"-disable-update-check", "-stats", "-stats-interval", "15",
		"-rate-limit", "50", "-concurrency", "25", "-bulk-size", "25",
		"-timeout", "10", "-retries", "1", "-max-host-error", "30",
		"-no-interactsh", "-exclude-hosts", "evil.invalid",
		"-templates", "/opt/nuclei-templates", "-template-id", "cve-2021-0001",
		"-tags", "cve,exposure", "-exclude-tags", "dos",
		"-severity", "medium,high", "-pt", "http,ssl"} {
		if !containsFlag(args, want) {
			t.Errorf("args missing %q; got %v", want, args)
		}
	}
	if !strings.Contains(joined, "-rate-limit 50") {
		t.Errorf("expected -rate-limit 50 in %v", args)
	}
}

func containsFlag(args []string, flag string) bool {
	for i, a := range args {
		if a == flag {
			return true
		}
		_ = i
	}
	return false
}

func TestBuildArgsOASTOmitsNoInteractsh(t *testing.T) {
	o := Options{
		TargetsFile: "/tmp/targets.txt",
		RateLimit:   50, Concurrency: 25, BulkSize: 25, TimeoutSec: 10,
		Retries: 1, MaxHostError: 30,
	}
	args, err := BuildArgs(o)
	if err != nil {
		t.Fatalf("BuildArgs OAST = err %v", err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "-no-interactsh") {
		t.Errorf("interactsh was not requested, -no-interactsh must not be passed; got %v", args)
	}
}

// TestBuildArgsDefaultsAreMinimal checks that a scan without any configuration
// is equivalent to a plain `nuclei -list targets.txt -jsonl`: no severity
// filter, no rate limit and no interactsh flag.
func TestBuildArgsDefaultsAreMinimal(t *testing.T) {
	args, err := BuildArgs(Options{TargetsFile: "/tmp/targets.txt"})
	if err != nil {
		t.Fatalf("BuildArgs defaults = err %v", err)
	}
	joined := strings.Join(args, " ")
	for _, f := range []string{"-severity", "-rate-limit", "-concurrency", "-bulk-size",
		"-timeout", "-retries", "-max-host-error", "-no-interactsh", "-exclude-hosts",
		"-pt", "-tags", "-templates", "-template-id", "-exclude-tags"} {
		if strings.Contains(joined, f+" ") || strings.HasSuffix(joined, f) {
			t.Errorf("unexpected flag %q present in args %v", f, args)
		}
	}
	for _, want := range []string{"-list", "/tmp/targets.txt", "-jsonl"} {
		if !containsFlag(args, want) {
			t.Errorf("args missing %q; got %v", want, args)
		}
	}
}

func TestBuildArgsRejects(t *testing.T) {
	cases := []struct {
		name string
		opt  Options
	}{
		{"tag starts with dash", Options{Tags: []string{"-x"}, TargetsFile: "/tmp/targets.txt",
			RateLimit: 50, Concurrency: 25, BulkSize: 25, TimeoutSec: 10, Retries: 1, MaxHostError: 30}},
		{"tag has space", Options{Tags: []string{"a b"}, TargetsFile: "/tmp/targets.txt",
			RateLimit: 50, Concurrency: 25, BulkSize: 25, TimeoutSec: 10, Retries: 1, MaxHostError: 30}},
		{"bad severity", Options{Severities: []string{"bad"}, TargetsFile: "/tmp/targets.txt",
			RateLimit: 50, Concurrency: 25, BulkSize: 25, TimeoutSec: 10, Retries: 1, MaxHostError: 30}},
		{"protocol code", Options{Protocols: []string{"code"}, TargetsFile: "/tmp/targets.txt",
			RateLimit: 50, Concurrency: 25, BulkSize: 25, TimeoutSec: 10, Retries: 1, MaxHostError: 30}},
		{"protocol headless", Options{Protocols: []string{"headless"}, TargetsFile: "/tmp/targets.txt",
			RateLimit: 50, Concurrency: 25, BulkSize: 25, TimeoutSec: 10, Retries: 1, MaxHostError: 30}},
		{"protocol file", Options{Protocols: []string{"file"}, TargetsFile: "/tmp/targets.txt",
			RateLimit: 50, Concurrency: 25, BulkSize: 25, TimeoutSec: 10, Retries: 1, MaxHostError: 30}},
		{"relative template path", Options{TemplatePaths: []string{"relative/path"}, TargetsFile: "/tmp/targets.txt",
			RateLimit: 50, Concurrency: 25, BulkSize: 25, TimeoutSec: 10, Retries: 1, MaxHostError: 30}},
		{"template path with comma", Options{TemplatePaths: []string{"/a,/b"}, TargetsFile: "/tmp/targets.txt",
			RateLimit: 50, Concurrency: 25, BulkSize: 25, TimeoutSec: 10, Retries: 1, MaxHostError: 30}},
		{"relative targets file", Options{TargetsFile: "relative.txt",
			RateLimit: 50, Concurrency: 25, BulkSize: 25, TimeoutSec: 10, Retries: 1, MaxHostError: 30}},
		{"rate limit too high", Options{TargetsFile: "/tmp/targets.txt", RateLimit: 20000,
			Concurrency: 25, BulkSize: 25, TimeoutSec: 10, Retries: 1, MaxHostError: 30}},
		{"host starts with dash", Options{ExcludeHosts: []string{"-evil"}, TargetsFile: "/tmp/targets.txt",
			RateLimit: 50, Concurrency: 25, BulkSize: 25, TimeoutSec: 10, Retries: 1, MaxHostError: 30}},
	}
	for _, tc := range cases {
		if _, err := BuildArgs(tc.opt); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}

func TestBuildArgsNoForbiddenFlags(t *testing.T) {
	o := Options{
		TargetsFile:   "/tmp/targets.txt",
		TemplatePaths: []string{"/opt/nuclei-templates"},
		TemplateIDs:   []string{"cve-2021-0001"},
		Tags:          []string{"cve", "exposure"},
		ExcludeTags:   []string{"dos"},
		Severities:    []string{"info", "low", "medium", "high", "critical"},
		Protocols:     []string{"dns", "http", "tcp", "ssl", "websocket", "whois", "javascript", "workflow"},
		ExcludeHosts:  []string{"evil.invalid", "10.0.0.0/8"},
		RateLimit:     50, Concurrency: 25, BulkSize: 25, TimeoutSec: 10,
		Retries: 1, MaxHostError: 30, NoInteractsh: true,
	}
	args, err := BuildArgs(o)
	if err != nil {
		t.Fatalf("BuildArgs = err %v", err)
	}
	joined := strings.Join(args, " ")
	forbidden := []string{"-code", "-headless", "-dast", "-fuzz", "-lfa",
		"-allow-local-file-access", "-env-vars", "-update-templates", "-update", "-reset", "-sandbox"}
	for _, f := range forbidden {
		if strings.Contains(joined, f+" ") || strings.HasSuffix(joined, f) {
			t.Errorf("forbidden flag %q present in args %v", f, args)
		}
	}
}

func TestBuildArgsNoListFlagsWhenEmpty(t *testing.T) {
	o := Options{
		TargetsFile: "/tmp/targets.txt",
		RateLimit:   50, Concurrency: 25, BulkSize: 25, TimeoutSec: 10,
		Retries: 1, MaxHostError: 30,
	}
	args, err := BuildArgs(o)
	if err != nil {
		t.Fatalf("BuildArgs = err %v", err)
	}
	joined := strings.Join(args, " ")
	for _, f := range []string{"-tags", "-template-id", "-templates", "-pt",
		"-exclude-tags", "-exclude-hosts", "-severity"} {
		if strings.Contains(joined, f+" ") || strings.HasSuffix(joined, f) {
			t.Errorf("unexpected flag %q present in args %v", f, args)
		}
	}
}
