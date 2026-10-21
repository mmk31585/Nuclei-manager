package domain

import (
	"strings"
	"time"

	"github.com/mmk31585/Nuclei-manager/internal/cron"
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
	// Minimum severity reported by this task (optional, no floor by default)
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
	NotifyOn StringList `json:"notify_on" enums:"info,low,medium,high,critical" gorm:"type:text;not null"`
	// Skip port discovery before run (default false)
	SkipDiscovery bool `json:"skip_discovery"`
	// Also scan discovered non-web ports with network templates (default false)
	ScanNetworkPorts bool `json:"scan_network_ports"`
	// Protocols to use for network port scan (e.g. "tcp,javascript")
	NetworkProtocols StringList `json:"network_protocols" gorm:"type:text;not null"`
	// Last scheduled run time
	LastRunAt *time.Time `json:"last_run_at"`
	// Next scheduled run time
	NextRunAt *time.Time `json:"next_run_at" gorm:"index"`
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
	if t.ScheduleType == ScheduleCron {
		if t.CronExpr == "" {
			return invalid("cron_expr is required for cron schedules")
		}
		if _, err := cron.Parse(t.CronExpr); err != nil {
			return invalid("invalid cron_expr: %v", err)
		}
	}
	if _, err := time.LoadLocation(t.Timezone); err != nil {
		return invalid("invalid timezone %q", t.Timezone)
	}
	if t.MinSeverity != "" && !t.MinSeverity.Valid() {
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
