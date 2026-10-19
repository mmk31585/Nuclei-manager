package domain

import "time"

type FindingStatus string

const (
	FindingStatusOpen          FindingStatus = "open"
	FindingStatusFixed         FindingStatus = "fixed"
	FindingStatusAccepted      FindingStatus = "accepted"
	FindingStatusFalsePositive FindingStatus = "false_positive"
)

// Finding represents a nuclei finding. Model only (no methods), for AutoMigrate.
type Finding struct {
	ID             uint          `json:"id" gorm:"primaryKey"`
	Fingerprint    string        `json:"fingerprint" gorm:"size:64;uniqueIndex"`
	TemplateID     string        `json:"template_id" gorm:"size:191;index"`
	Name           string        `json:"name" gorm:"size:255;not null"`
	Severity       Severity      `json:"severity" gorm:"size:16"`
	Host           string        `json:"host" gorm:"size:255;index"`
	MatchedAt      string        `json:"matched_at" gorm:"type:text"`
	CVEIDs         StringList    `json:"cve_ids" gorm:"type:text;not null"`
	Evidence       string        `json:"evidence" gorm:"type:text"`
	Status         FindingStatus `json:"status" gorm:"size:24;index"`
	FirstSeenRunID uint          `json:"first_seen_run_id"`
	LastSeenRunID  uint          `json:"last_seen_run_id"`
	MissedRuns     int           `json:"missed_runs"`
	Comment        string        `json:"comment" gorm:"type:text"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

// RunFinding links a run to its findings. Model only (no methods), for AutoMigrate.
type RunFinding struct {
	ID        uint `json:"id" gorm:"primaryKey"`
	RunID     uint `json:"run_id" gorm:"index"`
	FindingID uint `json:"finding_id" gorm:"index"`
	// uniqueIndex:idx_run_finding composite on RunID+FindingID
}

// CustomTemplate represents a user-uploaded nuclei template. Model only (no methods), for AutoMigrate.
type CustomTemplate struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Name      string    `json:"name" gorm:"size:191;uniqueIndex;not null"`
	Content   string    `json:"content" gorm:"type:longtext;not null"`
	Version   int       `json:"version"`
	Validated bool      `json:"validated"`
	Approved  bool      `json:"approved"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Suppression represents a finding suppression rule. Model only (no methods), for AutoMigrate.
type Suppression struct {
	ID          uint       `json:"id" gorm:"primaryKey"`
	TemplateID  string     `json:"template_id" gorm:"size:191;index"`
	HostPattern string     `json:"host_pattern" gorm:"size:255;not null"`
	Reason      string     `json:"reason" gorm:"type:text;not null"`
	ExpiresAt   *time.Time `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
}
