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

// Run stages describe which pass of a run is currently executing.
const (
	// RunStageWeb is the main pass over the web targets.
	RunStageWeb = "web"
	// RunStageNetwork is the optional second pass over the discovered network ports.
	RunStageNetwork = "network"
	// RunStageDone is set once every pass has finished.
	RunStageDone = "done"
)

// Run is one execution of a task. It records the command, versions, timing and
// finding counters produced by Nuclei.
type Run struct {
	// Run identifier (read-only)
	ID uint `json:"id" gorm:"primaryKey"`
	// Identifier of the task that produced this run
	TaskID uint `json:"task_id" gorm:"index;not null"`
	// Current lifecycle status (see RunStatus)
	Status RunStatus `json:"status" gorm:"size:24;index;not null"`
	// How the run was started: manual or schedule
	Trigger string `json:"trigger" gorm:"size:16;not null"`
	// Start time (null until claimed)
	StartedAt *time.Time `json:"started_at"`
	// Finish time (null until terminal)
	FinishedAt *time.Time `json:"finished_at"`
	// Nuclei process exit code (null if not run)
	ExitCode *int `json:"exit_code"`
	// Full nuclei command line that was executed
	CommandLine string `json:"command_line" gorm:"type:text"`
	// Detected nuclei engine version
	NucleiVersion string `json:"nuclei_version" gorm:"size:64"`
	// Detected nuclei templates version
	TemplatesVersion string `json:"templates_version" gorm:"size:64"`
	// Number of targets in the run
	TargetsCount int `json:"targets_count"`
	// Stage of the run currently executing (see RunStage constants)
	Stage string `json:"stage" gorm:"size:32;index"`
	// Number of requests issued (not populated yet)
	RequestsCount int `json:"requests_count"`
	// Total findings reported
	ResultsTotal int `json:"results_total"`
	// Critical findings
	FindingsCritical int `json:"findings_critical"`
	// High findings
	FindingsHigh int `json:"findings_high"`
	// Medium findings
	FindingsMedium int `json:"findings_medium"`
	// Low findings
	FindingsLow int `json:"findings_low"`
	// Info findings plus unknown severities
	FindingsInfo int `json:"findings_info"`
	// Lines that failed to parse
	ParseErrors int `json:"parse_errors"`
	// Path to the captured log file
	LogPath string `json:"log_path" gorm:"size:512"`
	// Path to the raw nuclei output file
	RawOutputPath string `json:"raw_output_path" gorm:"size:512"`
	// Error message when the run failed
	ErrorMessage string `json:"error_message" gorm:"type:text"`
	// Frozen configuration snapshot (not exposed over the API)
	ConfigSnapshot string `json:"-" gorm:"type:longtext"`
	// Creation timestamp (read-only)
	CreatedAt time.Time `json:"created_at"`
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
	// SetStage records the pass of the run that is currently executing.
	SetStage(ctx context.Context, id uint, stage string) error
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
//
// An empty profile filter and an empty floor mean "no severity filter": the
// result is empty and no -severity flag is passed to nuclei, so the scan runs
// every template and reports every finding.
func EffectiveSeverities(profile []string, floor Severity) ([]string, error) {
	if floor == "" {
		out := make([]string, 0, len(profile))
		for _, p := range profile {
			s := Severity(strings.ToLower(strings.TrimSpace(p)))
			if !s.Valid() {
				return nil, invalid("unknown severity %q", p)
			}
			out = append(out, string(s))
		}
		return out, nil
	}
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
