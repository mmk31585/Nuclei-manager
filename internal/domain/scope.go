package domain

import (
	"net/netip"
	"strings"
	"time"
)

// ScopeKind is the type of a scope allowlist entry.
type ScopeKind string

const (
	// ScopeDomain is a domain such as example.com (subdomains are included).
	ScopeDomain ScopeKind = "domain"
	// ScopeCIDR is an IP range such as 10.0.0.0/24.
	ScopeCIDR ScopeKind = "cidr"
	// ScopeIP is a single IP address such as 10.1.2.3.
	ScopeIP ScopeKind = "ip"
)

// ScopeEntry is one allowlist entry. An empty allowlist rejects every target
// (fail-closed).
type ScopeEntry struct {
	// Scope entry identifier (read-only)
	ID uint `json:"id" gorm:"primaryKey"`
	// Entry type: domain, cidr or ip
	Kind ScopeKind `json:"kind" gorm:"size:16;not null"`
	// Entry value, normalized on write (domain lowercased, CIDR/IP canonicalized)
	Value string `json:"value" gorm:"size:191;uniqueIndex;not null"`
	// Optional free-text comment
	Comment string `json:"comment" gorm:"type:text"`
	// Creation timestamp (read-only)
	CreatedAt time.Time `json:"created_at"`
}

func (e *ScopeEntry) Validate() error {
	e.Value = strings.ToLower(strings.TrimSpace(e.Value))
	switch e.Kind {
	case ScopeDomain:
		e.Value = strings.TrimPrefix(e.Value, ".")
		if e.Value == "" || !strings.Contains(e.Value, ".") || strings.ContainsAny(e.Value, " /:*@") {
			return invalid("domain must look like example.com (no scheme, port, wildcard)")
		}
	case ScopeCIDR:
		p, err := netip.ParsePrefix(e.Value)
		if err != nil {
			return invalid("invalid CIDR")
		}
		if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 16) {
			return invalid("CIDR is too broad")
		}
		e.Value = p.Masked().String()
	case ScopeIP:
		a, err := netip.ParseAddr(e.Value)
		if err != nil {
			return invalid("invalid IP address")
		}
		e.Value = a.Unmap().String()
	default:
		return invalid("kind must be one of: domain, cidr, ip")
	}
	return nil
}
