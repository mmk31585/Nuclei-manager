package config

import (
	"path/filepath"
	"testing"
)

func TestLoadRequiresDBDSN(t *testing.T) {
	t.Setenv("SM_DB_DSN", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected error when SM_DB_DSN is empty")
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("SM_DB_DSN", "user:pass@tcp(127.0.0.1:3306)/db")
	t.Setenv("SM_HTTP_ADDR", "127.0.0.1:8080")
	t.Setenv("SM_SWAGGER_HOST", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPAddr != "127.0.0.1:8080" {
		t.Errorf("HTTPAddr = %q", cfg.HTTPAddr)
	}
	if cfg.GinMode != "release" {
		t.Errorf("GinMode = %q", cfg.GinMode)
	}
	if cfg.NucleiBin != "nuclei" {
		t.Errorf("NucleiBin = %q", cfg.NucleiBin)
	}
	if cfg.MaxConcurrentRuns != 2 {
		t.Errorf("MaxConcurrentRuns = %d", cfg.MaxConcurrentRuns)
	}
	if cfg.WorkerPoll.String() != "2s" {
		t.Errorf("WorkerPoll = %v", cfg.WorkerPoll)
	}
	if cfg.SwaggerBasePath != "/api/v1" {
		t.Errorf("SwaggerBasePath = %q", cfg.SwaggerBasePath)
	}
	if cfg.SwaggerHost != "localhost:8080" {
		t.Errorf("SwaggerHost = %q, want localhost:8080", cfg.SwaggerHost)
	}
	if !filepath.IsAbs(cfg.DataDir) {
		t.Errorf("DataDir not absolute: %q", cfg.DataDir)
	}
}

func TestLoadExplicitSwaggerHostKeptVerbatim(t *testing.T) {
	t.Setenv("SM_DB_DSN", "user:pass@tcp(127.0.0.1:3306)/db")
	t.Setenv("SM_HTTP_ADDR", "127.0.0.1:8080")
	t.Setenv("SM_SWAGGER_HOST", "scan.example.com:443")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SwaggerHost != "scan.example.com:443" {
		t.Errorf("SwaggerHost = %q", cfg.SwaggerHost)
	}
}

func TestLoadSwaggerHostLocalhostGetsPort(t *testing.T) {
	t.Setenv("SM_DB_DSN", "user:pass@tcp(127.0.0.1:3306)/db")
	t.Setenv("SM_HTTP_ADDR", "localhost:9090")
	t.Setenv("SM_SWAGGER_HOST", "localhost")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SwaggerHost != "localhost" {
		t.Errorf("SwaggerHost = %q, want localhost", cfg.SwaggerHost)
	}
}

func TestLoadValidationErrors(t *testing.T) {
	t.Setenv("SM_DB_DSN", "user:pass@tcp(127.0.0.1:3306)/db")
	cases := []struct {
		key, val string
	}{
		{"SM_MAX_CONCURRENT_RUNS", "0"},
		{"SM_MAX_CONCURRENT_RUNS", "17"},
		{"SM_MAX_CONCURRENT_RUNS", "abc"},
		{"SM_WORKER_POLL", "100ms"},
		{"SM_WORKER_POLL", "notaduration"},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.val, func(t *testing.T) {
			t.Setenv(tc.key, tc.val)
			if _, err := Load(); err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}
