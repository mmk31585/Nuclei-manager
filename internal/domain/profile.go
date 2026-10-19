package domain

import (
	"strings"
	"time"
)

type Profile struct {
	ID             uint        `json:"id" gorm:"primaryKey"`
	Name           string      `json:"name" gorm:"size:191;uniqueIndex;not null"`
	Description    string      `json:"description" gorm:"type:text"`
	Tags           StringList  `json:"tags" gorm:"type:text;not null"`
	ExcludeTags    StringList  `json:"exclude_tags" gorm:"type:text;not null"`
	Severity       StringList  `json:"severity" gorm:"type:text;not null"`
	Protocols      StringList  `json:"protocols" gorm:"type:text;not null"`
	TemplateIDs    StringList  `json:"template_ids" gorm:"type:text;not null"`
	CustomSet      string      `json:"custom_set" gorm:"size:191"`
	RateLimit      int         `json:"rate_limit"`
	Concurrency    int         `json:"concurrency"`
	BulkSize       int         `json:"bulk_size"`
	TimeoutSec     int         `json:"timeout_sec"`
	Retries        int         `json:"retries"`
	MaxHostError   int         `json:"max_host_error"`
	MaxDurationMin int         `json:"max_duration_min"`
	OAST           bool        `json:"oast"`
	Builtin        bool        `json:"builtin"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
}

// ApplyDefaults fills zero-valued int fields with the phase defaults.
func (p *Profile) ApplyDefaults() {
	if p.RateLimit == 0 {
		p.RateLimit = 50
	}
	if p.Concurrency == 0 {
		p.Concurrency = 25
	}
	if p.BulkSize == 0 {
		p.BulkSize = 25
	}
	if p.TimeoutSec == 0 {
		p.TimeoutSec = 10
	}
	if p.Retries == 0 {
		p.Retries = 1
	}
	if p.MaxHostError == 0 {
		p.MaxHostError = 30
	}
	if p.MaxDurationMin == 0 {
		p.MaxDurationMin = 120
	}
}

func (p *Profile) Validate() error {
	p.Name = strings.TrimSpace(p.Name)
	p.Tags = cleanList(p.Tags)
	p.ExcludeTags = cleanList(p.ExcludeTags)
	p.Severity = cleanList(p.Severity)
	p.Protocols = cleanList(p.Protocols)
	p.TemplateIDs = cleanList(p.TemplateIDs)

	if p.Name == "" {
		return invalid("name is required")
	}
	if len(p.Name) > 191 {
		return invalid("name is too long")
	}
	for _, v := range p.Severity {
		if Severity(v).Valid() == false {
			return invalid("unknown severity %q", v)
		}
	}
	if p.RateLimit < 1 || p.RateLimit > 10000 {
		return invalid("rate_limit must be between 1 and 10000")
	}
	if p.Concurrency < 1 || p.Concurrency > 500 {
		return invalid("concurrency must be between 1 and 500")
	}
	if p.BulkSize < 1 || p.BulkSize > 500 {
		return invalid("bulk_size must be between 1 and 500")
	}
	if p.TimeoutSec < 1 || p.TimeoutSec > 300 {
		return invalid("timeout_sec must be between 1 and 300")
	}
	if p.Retries < 0 || p.Retries > 10 {
		return invalid("retries must be between 0 and 10")
	}
	if p.MaxHostError < 1 || p.MaxHostError > 1000 {
		return invalid("max_host_error must be between 1 and 1000")
	}
	if p.MaxDurationMin < 1 || p.MaxDurationMin > 1440 {
		return invalid("max_duration_min must be between 1 and 1440")
	}
	return nil
}
