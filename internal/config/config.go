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
	HTTPAddr           string
	DBDSN              string
	GinMode            string
	DataDir            string
	NucleiBin          string
	CustomTemplatesDir string
	MaxConcurrentRuns  int
	WorkerPoll         time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:  getenv("SM_HTTP_ADDR", "127.0.0.1:8080"),
		DBDSN:     os.Getenv("SM_DB_DSN"),
		GinMode:   getenv("SM_GIN_MODE", "release"),
		NucleiBin: getenv("SM_NUCLEI_BIN", "nuclei"),
	}
	if cfg.DBDSN == "" {
		return Config{}, errors.New("SM_DB_DSN is required")
	}
	var err error
	if cfg.DataDir, err = filepath.Abs(getenv("SM_DATA_DIR", "./data")); err != nil {
		return Config{}, err
	}
	if cfg.CustomTemplatesDir, err = filepath.Abs(getenv("SM_CUSTOM_TEMPLATES_DIR", "./custom-templates")); err != nil {
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
