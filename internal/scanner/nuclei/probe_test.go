package nuclei

import (
	"testing"
)

func TestMissingFlags(t *testing.T) {
	help := `-j, -jsonl write output
-rl, -rate-limit int
-stats display statistics
-stats-interval 15
-templates /path
`
	required := []string{"jsonl", "rate-limit", "stats", "stats-interval", "templates"}
	if missing := MissingFlags(help, required); len(missing) != 0 {
		t.Errorf("expected no missing, got %v", missing)
	}

	// Only -stats-json exists, no standalone -stats -> -stats is missing.
	helpNoStats := `-j, -jsonl write output
-stats-json write JSON stats
`
	missing := MissingFlags(helpNoStats, []string{"stats"})
	if len(missing) != 1 || missing[0] != "-stats" {
		t.Errorf("expected [-stats], got %v", missing)
	}
}

func TestParseVersion(t *testing.T) {
	v, tpl := parseVersion("[INF] Nuclei Engine Version: v3.4.10")
	if v != "v3.4.10" {
		t.Errorf("version = %q, want v3.4.10", v)
	}
	if tpl != "" {
		t.Errorf("templates = %q, want empty", tpl)
	}

	v, tpl = parseVersion("[INF] Nuclei Engine Version: v3.4.10 Templates Version: v2026.10.1")
	if v != "v3.4.10" {
		t.Errorf("version = %q, want v3.4.10", v)
	}
	if tpl != "v2026.10.1" {
		t.Errorf("templates = %q, want v2026.10.1", tpl)
	}

	v, tpl = parseVersion("no version here at all")
	if v != "unknown" {
		t.Errorf("version = %q, want unknown", v)
	}
	if tpl != "" {
		t.Errorf("templates = %q, want empty", tpl)
	}
}

func TestMissingFlagsDoesNotMatchSuffix(t *testing.T) {
	// -stats-json must not satisfy -stats.
	if missing := MissingFlags("-stats-json write stats", []string{"stats"}); len(missing) != 1 {
		t.Errorf("expected -stats missing, got %v", missing)
	}
	// -stats must satisfy itself.
	if missing := MissingFlags("-stats display stats", []string{"stats"}); len(missing) != 0 {
		t.Errorf("expected none missing, got %v", missing)
	}
}
