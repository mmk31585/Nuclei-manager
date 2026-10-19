package domain

import (
	"strings"
	"time"
)

// Target is a named group of hosts that can be scanned. Every host is
// validated against the scope allowlist before the target is stored.
type Target struct {
	// Target identifier (read-only, assigned by the server)
	ID uint `json:"id" gorm:"primaryKey"`
	// Unique target name (1-191 characters)
	Name string `json:"name" gorm:"size:191;uniqueIndex;not null"`
	// Optional free-text comment
	Comment string `json:"comment" gorm:"type:text"`
	// Hosts to scan (URLs, host:port, bare hosts or IPs); at least one required
	Hosts StringList `json:"hosts" gorm:"type:text;not null"`
	// Hosts, IPs or CIDRs excluded from the scan
	Exclude StringList `json:"exclude" gorm:"type:text;not null"`
	// Arbitrary labels for filtering and grouping
	Tags StringList `json:"tags" gorm:"type:text;not null"`
	// Probe hosts for reachability before scanning (defaults to true)
	ProbeFirst bool `json:"probe_first"`
	// Creation timestamp (read-only)
	CreatedAt time.Time `json:"created_at"`
	// Last update timestamp (read-only)
	UpdatedAt time.Time `json:"updated_at"`
}

func (t *Target) Validate() error {
	t.Name = strings.TrimSpace(t.Name)
	t.Hosts = cleanList(t.Hosts)
	t.Exclude = cleanList(t.Exclude)
	t.Tags = cleanList(t.Tags)
	if t.Name == "" {
		return invalid("name is required")
	}
	if len(t.Name) > 191 {
		return invalid("name is too long")
	}
	if len(t.Hosts) == 0 {
		return invalid("hosts must contain at least one entry")
	}
	if len(t.Hosts) > 10000 {
		return invalid("too many hosts")
	}
	return nil
}
