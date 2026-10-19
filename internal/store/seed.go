package store

import (
	"context"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

// SeedBuiltinProfiles inserts the built-in profiles idempotently.
// Tag names are starting values and will be verified against the installed
// Nuclei in a later phase.
func (s *Store) SeedBuiltinProfiles(ctx context.Context) error {
	profiles := []domain.Profile{
		{
			Name:        "quick",
			Description: "High and critical known CVEs",
			Tags:        []string{"cve"},
			Severity:    []string{"high", "critical"},
			ExcludeTags: []string{"dos", "intrusive", "bruteforce"},
			Builtin:     true,
		},
		{
			Name:        "web-app",
			Description: "General web application checks",
			Tags:        []string{"cve", "exposure", "misconfig", "default-login"},
			Severity:    []string{"medium", "high", "critical"},
			ExcludeTags: []string{"dos", "intrusive", "bruteforce"},
			Builtin:     true,
		},
		{
			Name:        "ssl-tls",
			Description: "TLS/SSL configuration checks",
			Protocols:   []string{"ssl"},
			ExcludeTags: []string{"dos", "intrusive"},
			Builtin:     true,
		},
		{
			Name:        "exposure-misconfig",
			Description: "Exposed files and misconfigurations",
			Tags:        []string{"exposure", "misconfig"},
			Severity:    []string{"low", "medium", "high", "critical"},
			ExcludeTags: []string{"dos", "intrusive"},
			Builtin:     true,
		},
	}
	for i := range profiles {
		p := &profiles[i]
		p.ApplyDefaults()
		if err := s.DB.WithContext(ctx).Where(domain.Profile{Name: p.Name}).FirstOrCreate(p).Error; err != nil {
			return mapErr(err)
		}
	}
	return nil
}
