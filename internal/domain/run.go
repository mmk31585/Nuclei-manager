package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// RunStatus is the lifecycle state of a run.
type RunStatus string

const (
	// RunQueued is waiting to be claimed by a worker.
	RunQueued RunStatus = "queued"
	// RunRunning is actively executing.
	RunRunning RunStatus = "running"
	// RunProcessing is reserved for the findings phase; unused now.
	RunProcessing RunStatus = "processing"
	// RunCompleted finished successfully.
	RunCompleted RunStatus = "completed"
	// RunFailed finished with an error.
	RunFailed RunStatus = "failed"
	// RunTimedOut exceeded the maximum duration.
	RunTimedOut RunStatus = "timed_out"
	// RunStopped was stopped by a user.
	RunStopped RunStatus = "stopped"
	// RunCancelled was cancelled while still queued.
	RunCancelled RunStatus = "cancelled"
)

func (s RunStatus) Valid() bool {
	switch s {
	case RunQueued, RunRunning, RunProcessing, RunCompleted, RunFailed, RunTimedOut, RunStopped, RunCancelled:
		return true
	}
	return false
}

func (s RunStatus) Terminal() bool {
	switch s {
	case RunCompleted, RunFailed, RunTimedOut, RunStopped, RunCancelled:
		return true
	}
	return false
}

const (
	TriggerManual   = "manual"
	TriggerSchedule = "schedule"
)

type Run struct {
	ID               uint       `json:"id" gorm:"primaryKey"`
	TaskID           uint       `json:"task_id" gorm:"index;not null"`
	Status           RunStatus  `json:"status" gorm:"size:24;index;not null"`
	Trigger          string     `json:"trigger" gorm:"size:16;not null"`
	StartedAt        *time.Time `json:"started_at"`
	FinishedAt       *time.Time `json:"finished_at"`
	ExitCode         *int       `json:"exit_code"`
	CommandLine      string     `json:"command_line" gorm:"type:text"`
	NucleiVersion    string     `json:"nuclei_version" gorm:"size:64"`
	TemplatesVersion string     `json:"templates_version" gorm:"size:64"`
	TargetsCount     int        `json:"targets_count"`
	RequestsCount    int        `json:"requests_count"` // not populated yet
	ResultsTotal     int        `json:"results_total"`
	FindingsCritical int        `json:"findings_critical"`
	FindingsHigh     int        `json:"findings_high"`
	FindingsMedium   int        `json:"findings_medium"`
	FindingsLow      int        `json:"findings_low"`
	FindingsInfo     int        `json:"findings_info"` // info + unknown severities
	ParseErrors      int        `json:"parse_errors"`
	LogPath          string     `json:"log_path" gorm:"size:512"`
	RawOutputPath    string     `json:"raw_output_path" gorm:"size:512"`
	ErrorMessage     string     `json:"error_message" gorm:"type:text"`
	ConfigSnapshot   string     `json:"-" gorm:"type:longtext"`
	CreatedAt        time.Time  `json:"created_at"`
}

type RunCounters struct {
	Total, Critical, High, Medium, Low, Info, ParseErrors int
}

type RunExecution struct {
	CommandLine      string
	NucleiVersion    string
	TemplatesVersion string
	LogPath          string
	RawOutputPath    string
	TargetsCount     int
}

type RunFinish struct {
	Status       RunStatus
	ExitCode     *int
	ErrorMessage string
	Counters     RunCounters
}

type RunFilter struct {
	TaskID uint
	Status RunStatus
	Limit  int // default 50, max 200
}

type RunRepo interface {
	// CreateForTask inserts a queued run unless the task already has an active run (ErrConflict).
	CreateForTask(ctx context.Context, run *Run) error
	Get(ctx context.Context, id uint) (*Run, error)
	List(ctx context.Context, f RunFilter) ([]Run, error)
	// ClaimNext atomically moves the oldest queued run to running. Returns (nil, nil) when none.
	ClaimNext(ctx context.Context) (*Run, error)
	SetExecution(ctx context.Context, id uint, e RunExecution) error
	UpdateProgress(ctx context.Context, id uint, c RunCounters) error
	Finish(ctx context.Context, id uint, f RunFinish) error
	// CancelQueued cancels a run only if it is still queued; reports whether it did.
	CancelQueued(ctx context.Context, id uint) (bool, error)
	// RecoverInterrupted marks runs left running/processing by a previous process as failed.
	RecoverInterrupted(ctx context.Context) (int64, error)
}

// ConfigSnapshot freezes the configuration a run executes with.
type ConfigSnapshot struct {
	Task    Task    `json:"task"`
	Target  Target  `json:"target"`
	Profile Profile `json:"profile"`
}

func (s ConfigSnapshot) Encode() (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func DecodeSnapshot(raw string) (ConfigSnapshot, error) {
	var s ConfigSnapshot
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return ConfigSnapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	return s, nil
}

var severityOrder = []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

func severityRank(s Severity) (int, bool) {
	for i, v := range severityOrder {
		if v == s {
			return i, true
		}
	}
	return 0, false
}

// EffectiveSeverities combines the profile's severity filter with the task's severity floor.
// Empty profile filter means "all severities at or above the floor".
func EffectiveSeverities(profile []string, floor Severity) ([]string, error) {
	min, ok := severityRank(floor)
	if !ok {
		return nil, invalid("unknown min_severity %q", floor)
	}
	var out []string
	if len(profile) == 0 {
		for _, s := range severityOrder {
			if r, _ := severityRank(s); r >= min {
				out = append(out, string(s))
			}
		}
	} else {
		for _, p := range profile {
			s := Severity(strings.ToLower(strings.TrimSpace(p)))
			r, ok := severityRank(s)
			if !ok {
				return nil, invalid("unknown severity %q", p)
			}
			if r >= min {
				out = append(out, string(s))
			}
		}
	}
	if len(out) == 0 {
		return nil, invalid("no severities left after applying min_severity %q", floor)
	}
	return out, nil
}
