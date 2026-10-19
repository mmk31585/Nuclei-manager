package nuclei

import (
	"errors"
	"testing"
)

func TestParseLineCVEAndTagsShapes(t *testing.T) {
	// cve-id as array
	ev, err := ParseLine([]byte(`{"template-id":"t1","info":{"name":"N","severity":"high","classification":{"cve-id":["CVE-1","CVE-2"]}},"host":"h","matched-at":"m"}`))
	if err != nil {
		t.Fatalf("array cve-id: %v", err)
	}
	if len(ev.Info.Classification.CVEID) != 2 || ev.Info.Classification.CVEID[0] != "CVE-1" {
		t.Errorf("cve-id array = %v", ev.Info.Classification.CVEID)
	}

	// cve-id as string
	ev, err = ParseLine([]byte(`{"template-id":"t2","info":{"name":"N","severity":"low","classification":{"cve-id":"CVE-3"}},"host":"h","matched-at":"m"}`))
	if err != nil {
		t.Fatalf("string cve-id: %v", err)
	}
	if len(ev.Info.Classification.CVEID) != 1 || ev.Info.Classification.CVEID[0] != "CVE-3" {
		t.Errorf("cve-id string = %v", ev.Info.Classification.CVEID)
	}

	// tags as string
	ev, err = ParseLine([]byte(`{"template-id":"t3","info":{"name":"N","severity":"medium","tags":"cve,web"},"host":"h","matched-at":"m"}`))
	if err != nil {
		t.Fatalf("tags string: %v", err)
	}
	if len(ev.Info.Tags) != 2 || ev.Info.Tags[0] != "cve" || ev.Info.Tags[1] != "web" {
		t.Errorf("tags string = %v", ev.Info.Tags)
	}

	// tags as array
	ev, err = ParseLine([]byte(`{"template-id":"t4","info":{"name":"N","severity":"info","tags":["x","y"]},"host":"h","matched-at":"m"}`))
	if err != nil {
		t.Fatalf("tags array: %v", err)
	}
	if len(ev.Info.Tags) != 2 {
		t.Errorf("tags array = %v", ev.Info.Tags)
	}
}

func TestParseLineErrors(t *testing.T) {
	if _, err := ParseLine([]byte("not json")); !errors.Is(err, ErrNotJSON) {
		t.Errorf("not json -> %v, want ErrNotJSON", err)
	}
	if _, err := ParseLine([]byte(`{"broken":`)); err == nil {
		t.Errorf("broken json expected error, got nil")
	}
	if _, err := ParseLine([]byte(`{"template":"no id","info":{"name":"N"}}`)); err == nil {
		t.Errorf("missing template-id expected error, got nil")
	}
	if _, err := ParseLine([]byte("")); !errors.Is(err, ErrNotJSON) {
		t.Errorf("empty -> %v, want ErrNotJSON", err)
	}
	if _, err := ParseLine([]byte("   ")); !errors.Is(err, ErrNotJSON) {
		t.Errorf("whitespace -> %v, want ErrNotJSON", err)
	}
}

func TestParseLineSeverityLowercasedAndUnknown(t *testing.T) {
	ev, err := ParseLine([]byte(`{"template-id":"t","info":{"name":"N","severity":"CRITICAL"},"host":"h","matched-at":"m"}`))
	if err != nil {
		t.Fatalf("uppercase severity: %v", err)
	}
	if ev.Info.Severity != "critical" {
		t.Errorf("severity = %q, want critical", ev.Info.Severity)
	}

	ev, err = ParseLine([]byte(`{"template-id":"t","info":{"name":"N","severity":"weird"},"host":"h","matched-at":"m"}`))
	if err != nil {
		t.Fatalf("unknown severity: %v", err)
	}
	if ev.Info.Severity != "weird" {
		t.Errorf("severity = %q, want weird", ev.Info.Severity)
	}
}

func TestCountersAdd(t *testing.T) {
	var c Counters
	sevs := []string{"critical", "high", "medium", "low", "info", "weird", ""}
	for _, s := range sevs {
		c.Add(&Event{Info: struct {
			Name           string   `json:"name"`
			Severity       string   `json:"severity"`
			Description    string   `json:"description"`
			Tags           flexList `json:"tags"`
			Reference      flexList `json:"reference"`
			Classification struct {
				CVEID flexList `json:"cve-id"`
				CWEID flexList `json:"cwe-id"`
			} `json:"classification"`
		}{
			Severity: s,
		}})
	}
	if c.Total != 7 || c.Critical != 1 || c.High != 1 || c.Medium != 1 ||
		c.Low != 1 || c.Info != 3 {
		t.Errorf("counters = %+v", c)
	}
}
