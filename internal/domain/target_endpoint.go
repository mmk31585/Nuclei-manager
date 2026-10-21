package domain

import (
	"time"
)

// TargetEndpoint is a discovered port/service on a target host.
type TargetEndpoint struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	TargetID    uint      `json:"target_id" gorm:"index;not null;constraint:OnDelete:CASCADE;uniqueIndex:idx_target_host_port"`
	Host        string    `json:"host" gorm:"size:255;not null;uniqueIndex:idx_target_host_port"`
	Port        int       `json:"port" gorm:"not null;uniqueIndex:idx_target_host_port"`
	Scheme      string    `json:"scheme" gorm:"size:10"` // http, https, or empty
	URL         string    `json:"url" gorm:"type:text"`
	IsWeb       bool      `json:"is_web"`
	Source      string    `json:"source" gorm:"size:20;not null"` // naabu, httpx, manual
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

func (TargetEndpoint) TableName() string { return "target_endpoints" }

// Endpoint is a discovery result (not persisted directly).
type Endpoint struct {
	Host   string
	Port   int
	Scheme string
	URL    string
	IsWeb  bool
	Source string
}
