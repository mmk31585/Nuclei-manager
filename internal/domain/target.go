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
	// Port discovery scope: default, top100, top1000, all, custom
	PortScope string `json:"port_scope" gorm:"size:16;default:'all'"`
	// Custom ports when port_scope is custom (e.g. "80,443,8000-9000")
	CustomPorts string `json:"custom_ports" gorm:"type:text"`
	// Discovery status: pending, running, done, failed
	DiscoveryStatus string `json:"discovery_status" gorm:"size:16;default:'pending'"`
	// Last discovery timestamp
	LastDiscoveryAt *time.Time `json:"last_discovery_at"`
	// Last discovery error message
	LastDiscoveryError string `json:"last_discovery_error" gorm:"type:text"`
	// Discovered endpoints
	Endpoints []TargetEndpoint `json:"endpoints,omitempty" gorm:"foreignKey:TargetID;constraint:OnDelete:CASCADE"`
	// Creation timestamp (read-only)
	CreatedAt time.Time `json:"created_at"`
	// Last update timestamp (read-only)
	UpdatedAt time.Time `json:"updated_at"`
}

const (
	PortScopeDefault = "default"
	PortScopeTop100  = "top100"
	PortScopeTop1000 = "top1000"
	PortScopeAll     = "all"
	PortScopeCustom  = "custom"
)

const (
	DiscoveryStatusPending = "pending"
	DiscoveryStatusRunning = "running"
	DiscoveryStatusDone    = "done"
	DiscoveryStatusFailed  = "failed"
)

func (t *Target) TargetScope() string {
	switch t.PortScope {
	case PortScopeAll:
		return "-p -"
	case PortScopeTop100:
		return "-top-ports 100"
	case PortScopeTop1000:
		return "-top-ports 1000"
	case PortScopeCustom:
		return t.CustomPorts
	default:
		return "-p 80,443"
	}
}

func (t *Target) ApplyDefaults() {
	if t.PortScope == "" {
		t.PortScope = PortScopeAll
	}
	if t.DiscoveryStatus == "" {
		t.DiscoveryStatus = DiscoveryStatusPending
	}
	if t.Exclude == nil {
		t.Exclude = StringList{}
	}
	if t.Tags == nil {
		t.Tags = StringList{}
	}
}

func (t *Target) Validate() error {
	t.Name = strings.TrimSpace(t.Name)
	t.Hosts = cleanList(t.Hosts)
	t.Exclude = cleanList(t.Exclude)
	t.Tags = cleanList(t.Tags)
	t.PortScope = strings.TrimSpace(strings.ToLower(t.PortScope))
	if t.PortScope == "" {
		t.PortScope = PortScopeAll
	}
	switch t.PortScope {
	case PortScopeDefault, PortScopeTop100, PortScopeTop1000, PortScopeAll, PortScopeCustom:
		// valid
	default:
		return invalid("port_scope must be one of: default, top100, top1000, all, custom")
	}
	if t.PortScope == PortScopeCustom && strings.TrimSpace(t.CustomPorts) == "" {
		return invalid("custom_ports is required when port_scope is custom")
	}
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
