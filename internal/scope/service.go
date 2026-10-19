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
