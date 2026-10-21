package cron

import (
	"testing"
	"time"
)

func TestParseInvalid(t *testing.T) {
	cases := []string{
		"",
		"* * * *",
		"* * * * * *",
		"60 * * * *",
		"* 24 * * *",
		"* * 0 * *",
		"* * * 13 *",
		"* * * * 7",
		"a * * * *",
		"5-1 * * * *",
	}
	for _, expr := range cases {
		if _, err := Parse(expr); err == nil {
			t.Errorf("Parse(%q) = nil error, want error", expr)
		}
	}
}

func TestParseValid(t *testing.T) {
	cases := []string{
		"* * * * *",
		"0 3 * * *",
		"*/15 * * * *",
		"0 0 1 1 *",
		"0 9-17 * * 1-5",
		"0,30 * * * *",
		"5-10/2 * * * *",
	}
	for _, expr := range cases {
		if _, err := Parse(expr); err != nil {
			t.Errorf("Parse(%q) error = %v, want nil", expr, err)
		}
	}
}

func TestNext(t *testing.T) {
	base := time.Date(2026, 10, 21, 10, 30, 0, 0, time.UTC)
	cases := []struct {
		expr string
		want time.Time
	}{
		{"* * * * *", time.Date(2026, 10, 21, 10, 31, 0, 0, time.UTC)},
		{"0 * * * *", time.Date(2026, 10, 21, 11, 0, 0, 0, time.UTC)},
		{"*/15 * * * *", time.Date(2026, 10, 21, 10, 45, 0, 0, time.UTC)},
		{"0 3 * * *", time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC)},
		{"0 0 1 1 *", time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"0 9-17 * * 1-5", time.Date(2026, 10, 21, 11, 0, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		s, err := Parse(c.expr)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.expr, err)
		}
		got, err := s.Next(base)
		if err != nil {
			t.Fatalf("Next(%q): %v", c.expr, err)
		}
		if !got.Equal(c.want) {
			t.Errorf("Next(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestNextIsStrictlyAfter(t *testing.T) {
	s, err := Parse("* * * * *")
	if err != nil {
		t.Fatal(err)
	}
	exact := time.Date(2026, 10, 21, 10, 30, 0, 0, time.UTC)
	got, err := s.Next(exact)
	if err != nil {
		t.Fatal(err)
	}
	if !got.After(exact) {
		t.Errorf("Next = %v, want strictly after %v", got, exact)
	}
}
