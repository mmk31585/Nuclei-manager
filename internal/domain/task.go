package domain

import (
	"strings"
	"time"
)

type ScheduleType string

const (
	ScheduleOnce ScheduleType = "once"
	ScheduleCron ScheduleType = "cron"
)

type Task struct {
	ID                uint         `json:"id" gorm:"primaryKey"`
	Name              string       `json:"name" gorm:"size:191;uniqueIndex;not null"`
	Comment           string       `json:"comment" gorm:"type:text"`
	TargetID          uint         `json:"target_id" gorm:"index;not null"`
	ProfileID         uint         `json:"profile_id" gorm:"index;not null"`
	ScheduleType      ScheduleType `json:"schedule_type"`
	CronExpr          string       `json:"cron_expr" gorm:"size:64"`
	Timezone          string       `json:"timezone" gorm:"size:64"`
	MinSeverity       Severity     `json:"min_severity"`
	AddToAssets       bool         `json:"add_to_assets"`
	ApplySuppressions bool         `json:"apply_suppressions"`
	Enabled           bool         `json:"enabled"`
	RetentionKeepLast int          `json:"retention_keep_last"`
	NotifyOn          StringList   `json:"notify_on" gorm:"type:text;not null"`
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
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
