package domain

import (
	"strings"
	"time"
)

// ScheduleType controls how a task is (or will be) executed.
type ScheduleType string

const (
	// ScheduleOnce runs the task immediately on trigger.
	ScheduleOnce ScheduleType = "once"
	// ScheduleCron runs the task on a cron expression.
	ScheduleCron ScheduleType = "cron"
)

// Task binds a Target to a Profile and describes how and when the scan runs.
type Task struct {
	// Task identifier (read-only)
	ID uint `json:"id" gorm:"primaryKey"`
	// Unique task name (1-191 characters)
	Name string `json:"name" gorm:"size:191;uniqueIndex;not null"`
	// Optional free-text comment
	Comment string `json:"comment" gorm:"type:text"`
	// Identifier of the target to scan (must exist)
	TargetID uint `json:"target_id" gorm:"index;not null"`
	// Identifier of the profile to use (must exist)
	ProfileID uint `json:"profile_id" gorm:"index;not null"`
	// Schedule type: once or cron (defaults to once)
	ScheduleType ScheduleType `json:"schedule_type"`
	// Cron expression, required when schedule_type is cron
	CronExpr string `json:"cron_expr" gorm:"size:64"`
	// IANA timezone for the schedule (defaults to UTC)
	Timezone string `json:"timezone" gorm:"size:64"`
	// Minimum severity reported by this task (defaults to medium)
	MinSeverity Severity `json:"min_severity"`
	// Add discovered hosts to the asset inventory
	AddToAssets bool `json:"add_to_assets"`
	// Apply configured suppressions to findings
	ApplySuppressions bool `json:"apply_suppressions"`
	// Whether the schedule is enabled
	Enabled bool `json:"enabled"`
	// Number of most recent runs to retain (1-1000, defaults to 20)
	RetentionKeepLast int `json:"retention_keep_last"`
	// Severities that trigger a notification
	NotifyOn StringList `json:"notify_on" gorm:"type:text;not null"`
	// Creation timestamp (read-only)
	CreatedAt time.Time `json:"created_at"`
	// Last update timestamp (read-only)
	UpdatedAt time.Time `json:"updated_at"`
}

// ApplyDefaults fills zero-valued schedule and retention fields.
func (t *Task) ApplyDefaults() {
	if t.ScheduleType == "" {
		t.ScheduleType = ScheduleOnce
	}
	if t.Timezone == "" {
		t.Timezone = "UTC"
	}
	if t.MinSeverity == "" {
		t.MinSeverity = SeverityMedium
	}
	if t.RetentionKeepLast == 0 {
		t.RetentionKeepLast = 20
	}
}

func (t *Task) Validate() error {
	t.Name = strings.TrimSpace(t.Name)
	t.NotifyOn = cleanList(t.NotifyOn)

	if t.Name == "" {
		return invalid("name is required")
	}
	if t.TargetID == 0 {
		return invalid("target_id is required")
	}
	if t.ProfileID == 0 {
		return invalid("profile_id is required")
	}
	switch t.ScheduleType {
	case ScheduleOnce, ScheduleCron:
	default:
		return invalid("schedule_type must be one of: once, cron")
	}
	if t.ScheduleType == ScheduleCron && t.CronExpr == "" {
		return invalid("cron_expr is required for cron schedules")
		// real cron parsing comes in the scheduler phase
	}
	if _, err := time.LoadLocation(t.Timezone); err != nil {
		return invalid("invalid timezone %q", t.Timezone)
	}
	if !t.MinSeverity.Valid() {
		return invalid("invalid min_severity %q", t.MinSeverity)
	}
	for _, v := range t.NotifyOn {
		if Severity(v).Valid() == false {
			return invalid("unknown notify_on severity %q", v)
		}
	}
	if t.RetentionKeepLast < 1 || t.RetentionKeepLast > 1000 {
		return invalid("retention_keep_last must be between 1 and 1000")
	}
	return nil
}
