package config

import (
	"errors"
	"os"
)

type Config struct {
	HTTPAddr string
	DBDSN    string
	GinMode  string
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr: getenv("SM_HTTP_ADDR", "127.0.0.1:8080"),
		DBDSN:    os.Getenv("SM_DB_DSN"),
		GinMode:  getenv("SM_GIN_MODE", "release"),
	}
	if cfg.DBDSN == "" {
		return Config{}, errors.New("SM_DB_DSN is required")
	}
	return cfg, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
