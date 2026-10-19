package nuclei

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

var ErrNotJSON = errors.New("not a JSON object")

// flexList accepts null, a string ("a,b") or an array of strings. Other shapes are ignored.
type flexList []string

func (f *flexList) UnmarshalJSON(b []byte) error {
	*f = nil
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		return nil
	}
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" {
			*f = append(*f, s)
		}
	}
	switch b[0] {
	case '"':
		var s string
		if json.Unmarshal(b, &s) == nil {
			for _, p := range strings.Split(s, ",") {
				add(p)
			}
		}
	case '[':
		var arr []any
		if json.Unmarshal(b, &arr) == nil {
			for _, v := range arr {
				if s, ok := v.(string); ok {
					add(s)
				}
			}
		}
	}
	return nil
}

// Event is the subset of a nuclei JSONL result we use now. It is extended in the findings phase.
type Event struct {
	TemplateID string `json:"template-id"`
	Template   string `json:"template"`
	Info       struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Description    string   `json:"description"`
		Tags           flexList `json:"tags"`
		Reference      flexList `json:"reference"`
		Classification struct {
			CVEID flexList `json:"cve-id"`
			CWEID flexList `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
	MatcherName      string   `json:"matcher-name"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults flexList `json:"extracted-results"`
	IP               string   `json:"ip"`
	Timestamp        string   `json:"timestamp"`
	CurlCommand      string   `json:"curl-command"`
}

func ParseLine(line []byte) (*Event, error) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return nil, ErrNotJSON
	}
	var ev Event
	if err := json.Unmarshal(line, &ev); err != nil {
		return nil, err
	}
	if ev.TemplateID == "" {
		return nil, errors.New("missing template-id")
	}
	ev.Info.Severity = strings.ToLower(strings.TrimSpace(ev.Info.Severity))
	return &ev, nil
}

type Counters struct {
	Total, Critical, High, Medium, Low, Info, ParseErrors int
}

func (c *Counters) Add(ev *Event) {
	c.Total++
	switch ev.Info.Severity {
	case "critical":
		c.Critical++
	case "high":
		c.High++
	case "medium":
		c.Medium++
	case "low":
		c.Low++
	default:
		c.Info++ // info and unknown
	}
}
