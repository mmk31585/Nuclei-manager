package domain

import "time"

type RunStatus string

const (
	RunStatusQueued     RunStatus = "queued"
	RunStatusRunning    RunStatus = "running"
	RunStatusProcessing RunStatus = "processing"
	RunStatusCompleted  RunStatus = "completed"
	RunStatusFailed     RunStatus = "failed"
	RunStatusTimedOut   RunStatus = "timed_out"
	RunStatusStopped    RunStatus = "stopped"
	RunStatusCancelled  RunStatus = "cancelled"
)

// Run represents a nuclei scan execution. Model only (no methods), for AutoMigrate.
type Run struct {
	ID               uint       `json:"id" gorm:"primaryKey"`
	TaskID           uint       `json:"task_id" gorm:"index;not null"`
	Status           RunStatus  `json:"status" gorm:"size:24;index;not null"`
	StartedAt        *time.Time `json:"started_at"`
	FinishedAt       *time.Time `json:"finished_at"`
	ExitCode         *int       `json:"exit_code"`
	CommandLine      string     `json:"command_line" gorm:"type:text"`
	NucleiVersion    string     `json:"nuclei_version"`
	TemplatesVersion string     `json:"templates_version"`
	TargetsCount     int        `json:"targets_count"`
	RequestsCount    int        `json:"requests_count"`
	FindingsCritical int        `json:"findings_critical"`
	FindingsHigh     int        `json:"findings_high"`
	FindingsMedium   int        `json:"findings_medium"`
	FindingsLow      int        `json:"findings_low"`
	FindingsInfo     int        `json:"findings_info"`
	LogPath          string     `json:"log_path" gorm:"size:512"`
	RawOutputPath    string     `json:"raw_output_path" gorm:"size:512"`
	ErrorMessage     string     `json:"error_message" gorm:"type:text"`
	CreatedAt        time.Time  `json:"created_at"`
}

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
