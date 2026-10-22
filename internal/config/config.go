package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr                 string
	DBDSN                    string
	GinMode                  string
	DataDir                  string
	NucleiBin                string
	CustomTemplatesDir       string
	NucleiTemplatesDir       string
	MaxConcurrentRuns        int
	WorkerPoll               time.Duration
	SchedulerPoll            time.Duration
	SwaggerHost              string
	SwaggerBasePath          string
	NaabuPath                string
	HttpxPath                string
	DiscoveryRate            int
	DiscoveryTimeoutMs       int
	DiscoveryMaxConcurrent   int
	DiscoveryTimeout         time.Duration
	NaabuScanType            string
	DiscoveryRetries         int
	DiscoverySkipHostDiscovery bool
	DiscoveryVerify          bool
	DiscoveryWarmUpTime      int
	DiscoveryExcludeCDN      bool
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:        getenv("SM_HTTP_ADDR", "127.0.0.1:8080"),
		DBDSN:           os.Getenv("SM_DB_DSN"),
		GinMode:         getenv("SM_GIN_MODE", "release"),
		NucleiBin:       getenv("SM_NUCLEI_BIN", "nuclei"),
		SwaggerHost:     os.Getenv("SM_SWAGGER_HOST"), // empty = auto-detect from request
		SwaggerBasePath: getenv("SM_SWAGGER_BASE_PATH", "/api/v1"),
	}
	if cfg.DBDSN == "" {
		return Config{}, errors.New("SM_DB_DSN is required")
	}
	var err error
	if cfg.DataDir, err = filepath.Abs(getenv("SM_DATA_DIR", "./data")); err != nil {
		return Config{}, err
	}
	// Custom templates live alongside the binary by default; they are not
	// configurable via environment (use SM_NUCLEI_TEMPLATES_DIR for the
	// official Nuclei templates).
	if cfg.CustomTemplatesDir, err = filepath.Abs("./custom-templates"); err != nil {
		return Config{}, err
	}
	if v := getenv("SM_NUCLEI_TEMPLATES_DIR", ""); v != "" {
		if cfg.NucleiTemplatesDir, err = filepath.Abs(v); err != nil {
			return Config{}, err
		}
	}
	n, err := strconv.Atoi(getenv("SM_MAX_CONCURRENT_RUNS", "2"))
	if err != nil || n < 1 || n > 16 {
		return Config{}, errors.New("SM_MAX_CONCURRENT_RUNS must be an integer between 1 and 16")
	}
	cfg.MaxConcurrentRuns = n
	d, err := time.ParseDuration(getenv("SM_WORKER_POLL", "2s"))
	if err != nil || d < 500*time.Millisecond {
		return Config{}, fmt.Errorf("SM_WORKER_POLL must be a duration of at least 500ms")
	}
	cfg.WorkerPoll = d
	schedPoll, err := time.ParseDuration(getenv("SM_SCHEDULER_POLL", "30s"))
	if err != nil || schedPoll < 5*time.Second {
		return Config{}, fmt.Errorf("SM_SCHEDULER_POLL must be a duration of at least 5s")
	}
	cfg.SchedulerPoll = schedPoll
	cfg.NaabuPath = getenv("NAABU_PATH", "naabu")
	cfg.HttpxPath = getenv("HTTPX_PATH", "httpx")
	n, err = strconv.Atoi(getenv("DISCOVERY_RATE", "1000"))
	if err != nil || n < 1 || n > 100000 {
		return Config{}, errors.New("DISCOVERY_RATE must be an integer between 1 and 100000")
	}
	cfg.DiscoveryRate = n
	n, err = strconv.Atoi(getenv("DISCOVERY_TIMEOUT_MS", "1000"))
	if err != nil || n < 100 || n > 30000 {
		return Config{}, errors.New("DISCOVERY_TIMEOUT_MS must be an integer between 100 and 30000")
	}
	cfg.DiscoveryTimeoutMs = n
	n, err = strconv.Atoi(getenv("DISCOVERY_MAX_CONCURRENT", "2"))
	if err != nil || n < 1 || n > 16 {
		return Config{}, errors.New("DISCOVERY_MAX_CONCURRENT must be an integer between 1 and 16")
	}
	cfg.DiscoveryMaxConcurrent = n
	d, err = time.ParseDuration(getenv("DISCOVERY_TIMEOUT", "30m"))
	if err != nil {
		return Config{}, fmt.Errorf("DISCOVERY_TIMEOUT must be a valid duration")
	}
	cfg.DiscoveryTimeout = d
	cfg.NaabuPath = getenv("NAABU_PATH", "naabu")
	cfg.HttpxPath = getenv("HTTPX_PATH", "httpx")
	n, err = strconv.Atoi(getenv("DISCOVERY_RATE", "1000"))
	if err != nil || n < 1 || n > 100000 {
		return Config{}, errors.New("DISCOVERY_RATE must be an integer between 1 and 100000")
	}
	cfg.DiscoveryRate = n
	n, err = strconv.Atoi(getenv("DISCOVERY_TIMEOUT_MS", "1000"))
	if err != nil || n < 100 || n > 30000 {
		return Config{}, errors.New("DISCOVERY_TIMEOUT_MS must be an integer between 100 and 30000")
	}
	cfg.DiscoveryTimeoutMs = n
	n, err = strconv.Atoi(getenv("DISCOVERY_MAX_CONCURRENT", "2"))
	if err != nil || n < 1 || n > 16 {
		return Config{}, errors.New("DISCOVERY_MAX_CONCURRENT must be an integer between 1 and 16")
	}
	cfg.DiscoveryMaxConcurrent = n
	d, err = time.ParseDuration(getenv("DISCOVERY_TIMEOUT", "30m"))
	if err != nil {
		return Config{}, fmt.Errorf("DISCOVERY_TIMEOUT must be a valid duration")
	}
	cfg.DiscoveryTimeout = d
	cfg.NaabuScanType = getenv("NAABU_SCAN_TYPE", "c")
	// Discovery retries (default 1 for speed)
	cfg.DiscoveryRetries = getenvInt("DISCOVERY_RETRIES", 1)
	// Skip host discovery in naabu (useful when scanning IPs directly)
	cfg.DiscoverySkipHostDiscovery = getenvBool("DISCOVERY_SKIP_HOST_DISCOVERY", true)
	// Verify open ports with TCP verification
	cfg.DiscoveryVerify = getenvBool("DISCOVERY_VERIFY", false)
	// Warm up time between scan phases (seconds)
	cfg.DiscoveryWarmUpTime = getenvInt("DISCOVERY_WARM_UP_TIME", 2)
	// Exclude CDN/WAF (only scan 80,443)
	cfg.DiscoveryExcludeCDN = getenvBool("DISCOVERY_EXCLUDE_CDN", false)
	return cfg, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return def
}

func getenvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}
