package domain

import (
	"net/netip"
	"strings"
	"time"
)

type ScopeKind string

const (
	ScopeDomain ScopeKind = "domain"
	ScopeCIDR   ScopeKind = "cidr"
	ScopeIP     ScopeKind = "ip"
)

type ScopeEntry struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Kind      ScopeKind `json:"kind" gorm:"size:16;not null"`
	Value     string    `json:"value" gorm:"size:191;uniqueIndex;not null"`
	Comment   string    `json:"comment" gorm:"type:text"`
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
