package domain

import (
	"strings"
	"time"
)

type Target struct {
	ID         uint       `json:"id" gorm:"primaryKey"`
	Name       string     `json:".name" gorm:"size:191;uniqueIndex;not null"`
	Comment    string     `json:"comment" gorm:"type:text"`
	Hosts      StringList `json:"hosts" gorm:"type:text;not null"`
	Exclude    StringList `json:"exclude" gorm:"type:text;not null"`
	Tags       StringList `json:"tags" gorm:"type:text;not null"`
	ProbeFirst bool       `json:"probe_first"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func (t *Target) Validate() error {
	t.Name = strings.TrimSpace(t.Name)
	t.Hosts = cleanList(t.Hosts)
	t.Exclude = cleanList(t.Exclude)
	t.Tags = cleanList(t.Tags)
	if t.Name == "" {
		return invalid("name is required")
	}
	if len(t.Name) > 191 {
		return invalid("name is too long")
	}
	if len(t.Hosts) == 0 {
		return invalid("hosts must contain at least one entry")
	}
	if len(t.Hosts) > 10000 {
		return invalid("too many hosts")
	}
	return nil
}
