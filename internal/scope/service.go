package scope

import (
	"context"
	"fmt"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

type Service struct{ repo domain.ScopeRepo }

func NewService(repo domain.ScopeRepo) *Service { return &Service{repo: repo} }

// CheckAll loads the current allowlist and checks every input.
// An empty allowlist rejects everything (fail-closed).
func (s *Service) CheckAll(ctx context.Context, inputs []string) error {
	entries, err := s.repo.List(ctx)
	if err != nil {
		return err
	}
	m, err := NewMatcher(entries)
	if err != nil {
		return err
	}
	for _, in := range inputs {
		if err := m.CheckTarget(in); err != nil {
			return fmt.Errorf("%q: %w", in, err)
		}
	}
	return nil
}

// IsAllowed checks if a single host (bare hostname/IP) is allowed by the current scope.
// Returns true if allowed, false if not allowed or on error.
func (s *Service) IsAllowed(ctx context.Context, host string) bool {
	entries, err := s.repo.List(ctx)
	if err != nil {
		return false
	}
	m, err := NewMatcher(entries)
	if err != nil {
		return false
	}
	return m.CheckTarget(host) == nil
}
