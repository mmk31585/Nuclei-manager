package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr             string
	DBDSN                string
	GinMode              string
	DataDir              string
	NucleiBin            string
	CustomTemplatesDir   string
	OfficialTemplatesDir string
	MaxConcurrentRuns    int
	WorkerPoll           time.Duration
	SwaggerHost          string
	SwaggerBasePath      string
}

func Load() (Config, error) {
	swaggerHostSet := os.Getenv("SM_SWAGGER_HOST") != ""
	cfg := Config{
		HTTPAddr:        getenv("SM_HTTP_ADDR", "127.0.0.1:8080"),
		DBDSN:           os.Getenv("SM_DB_DSN"),
		GinMode:         getenv("SM_GIN_MODE", "release"),
		NucleiBin:       getenv("SM_NUCLEI_BIN", "nuclei"),
		SwaggerHost:     getenv("SM_SWAGGER_HOST", "localhost"),
		SwaggerBasePath: getenv("SM_SWAGGER_BASE_PATH", "/api/v1"),
	}
	if cfg.DBDSN == "" {
		return Config{}, errors.New("SM_DB_DSN is required")
	}
	// Default localhost to "localhost:<listen port>" so the Swagger UI builds
	// working "Try it out" URLs. An explicit SM_SWAGGER_HOST is kept verbatim
	// (including any host:port the operator wants, e.g. scan.example.com:443).
	if !swaggerHostSet && (cfg.SwaggerHost == "localhost" || cfg.SwaggerHost == "127.0.0.1") {
		if _, port, err := net.SplitHostPort(cfg.HTTPAddr); err == nil {
			cfg.SwaggerHost = net.JoinHostPort(cfg.SwaggerHost, port)
		}
	}
	var err error
	if cfg.DataDir, err = filepath.Abs(getenv("SM_DATA_DIR", "./data")); err != nil {
		return Config{}, err
	}
	if cfg.CustomTemplatesDir, err = filepath.Abs(getenv("SM_CUSTOM_TEMPLATES_DIR", "./custom-templates")); err != nil {
		return Config{}, err
	}
	if cfg.OfficialTemplatesDir, err = filepath.Abs(getenv("SM_OFFICIAL_TEMPLATES_DIR", "")); err != nil {
		return Config{}, err
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
	return cfg, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
