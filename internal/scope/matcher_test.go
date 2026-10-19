package scope

import (
	"errors"
	"testing"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

func TestMatcherCheckTarget(t *testing.T) {
	m, err := NewMatcher([]domain.ScopeEntry{
		{Kind: domain.ScopeDomain, Value: "example.com"},
		{Kind: domain.ScopeCIDR, Value: "10.0.0.0/24"},
		{Kind: domain.ScopeIP, Value: "192.168.1.5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		in   string
		want error
	}{
		{"example.com", nil},
		{"https://api.example.com:8443/x?y=1", nil},
		{"notexample.com", ErrOutOfScope},
		{"example.com.evil.io", ErrOutOfScope},
		{"10.0.0.7", nil},
		{"http://10.0.0.7:8080", nil},
		{"10.0.0.0/25", nil},
		{"10.0.0.0/16", ErrOutOfScope},
		{"10.0.1.1", ErrOutOfScope},
		{"192.168.1.5", nil},
		{"192.168.1.6", ErrOutOfScope},
		{"http://[::1]:80", ErrOutOfScope},
		{"*.example.com", domain.ErrValidation},
		{"", domain.ErrValidation},
	}
	for _, tc := range tests {
		got := m.CheckTarget(tc.in)
		if !errors.Is(got, tc.want) && !(got == nil && tc.want == nil) {
			t.Errorf("CheckTarget(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestEmptyMatcherRejectsAll(t *testing.T) {
	m, _ := NewMatcher(nil)
	if err := m.CheckTarget("example.com"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("empty scope must reject, got %v", err)
	}
}
