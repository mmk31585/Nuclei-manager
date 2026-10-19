package scope

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

var ErrOutOfScope = errors.New("target is outside the allowed scope")

type Matcher struct {
	domains  []string
	prefixes []netip.Prefix
}

func NewMatcher(entries []domain.ScopeEntry) (*Matcher, error) {
	m := &Matcher{}
	for _, e := range entries {
		v := strings.ToLower(strings.TrimSpace(e.Value))
		switch e.Kind {
		case domain.ScopeDomain:
			m.domains = append(m.domains, strings.TrimPrefix(v, "."))
		case domain.ScopeCIDR:
			p, err := netip.ParsePrefix(v)
			if err != nil {
				return nil, fmt.Errorf("scope entry %d: %w", e.ID, err)
			}
			m.prefixes = append(m.prefixes, p.Masked())
		case domain.ScopeIP:
			a, err := netip.ParseAddr(v)
			if err != nil {
				return nil, fmt.Errorf("scope entry %d: %w", e.ID, err)
			}
			a = a.Unmap()
			m.prefixes = append(m.prefixes, netip.PrefixFrom(a, a.BitLen()))
		default:
			return nil, fmt.Errorf("scope entry %d: unknown kind %q", e.ID, e.Kind)
		}
	}
	return m, nil
}

// Known limit: domains are matched by name only; DNS resolution is not
// checked in this phase.

// ExtractHost returns the lowercase host from a URL, host:port, bare host or IP.
func ExtractHost(input string) (string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", errors.New("empty target")
	}
	if strings.ContainsAny(s, " \t*") {
		return "", errors.New("target contains forbidden characters")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", errors.New("invalid URL")
		}
		s = u.Host
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.Trim(s, "[]")
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if s == "" {
		return "", errors.New("empty host")
	}
	return s, nil
}

// CheckTarget returns nil only if the input is fully inside the scope.
func (m *Matcher) CheckTarget(input string) error {
	s := strings.TrimSpace(input)
	if p, err := netip.ParsePrefix(s); err == nil {
		if m.containsPrefix(p.Masked()) {
			return nil
		}
		return ErrOutOfScope
	}
	host, err := ExtractHost(s)
	if err != nil {
		return fmt.Errorf("%w: %v", domain.ErrValidation, err)
	}
	if m.allowedHost(host) {
		return nil
	}
	return ErrOutOfScope
}

func (m *Matcher) containsPrefix(p netip.Prefix) bool {
	for _, sp := range m.prefixes {
		if sp.Addr().BitLen() == p.Addr().BitLen() && sp.Bits() <= p.Bits() && sp.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func (m *Matcher) allowedHost(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		for _, p := range m.prefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	for _, d := range m.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
