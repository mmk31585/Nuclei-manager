package domain

import (
	"errors"
	"testing"
)

func TestTaskApplyDefaults(t *testing.T) {
	tk := Task{}
	tk.ApplyDefaults()
	if tk.ScheduleType != ScheduleOnce {
		t.Errorf("ScheduleType = %q", tk.ScheduleType)
	}
	if tk.Timezone != "UTC" {
		t.Errorf("Timezone = %q", tk.Timezone)
	}
	if tk.MinSeverity != SeverityMedium {
		t.Errorf("MinSeverity = %q", tk.MinSeverity)
	}
	if tk.RetentionKeepLast != 20 {
		t.Errorf("RetentionKeepLast = %d", tk.RetentionKeepLast)
	}
}

func TestTaskValidate(t *testing.T) {
	base := func() Task {
		tk := Task{Name: "t", TargetID: 1, ProfileID: 1}
		tk.ApplyDefaults()
		return tk
	}
	cases := []struct {
		name    string
		mutate  func(*Task)
		wantErr bool
	}{
		{"valid", func(t *Task) {}, false},
		{"empty name", func(t *Task) { t.Name = "  " }, true},
		{"zero target", func(t *Task) { t.TargetID = 0 }, true},
		{"zero profile", func(t *Task) { t.ProfileID = 0 }, true},
		{"bad schedule", func(t *Task) { t.ScheduleType = "weekly" }, true},
		{"cron missing expr", func(t *Task) { t.ScheduleType = ScheduleCron }, true},
		{"cron with expr", func(t *Task) { t.ScheduleType = ScheduleCron; t.CronExpr = "0 * * * *" }, false},
		{"bad timezone", func(t *Task) { t.Timezone = "Mars/Olympus" }, true},
		{"bad min severity", func(t *Task) { t.MinSeverity = "extreme" }, true},
		{"bad notify", func(t *Task) { t.NotifyOn = []string{"extreme"} }, true},
		{"retention too low", func(t *Task) { t.RetentionKeepLast = 0 }, true},
		{"retention too high", func(t *Task) { t.RetentionKeepLast = 1001 }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tk := base()
			tc.mutate(&tk)
			err := tk.Validate()
			if tc.wantErr {
				if err == nil || !errors.Is(err, ErrValidation) {
					t.Errorf("Validate() = %v, want ErrValidation", err)
				}
			} else if err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestSeverityValid(t *testing.T) {
	for _, s := range []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if !s.Valid() {
			t.Errorf("%q should be valid", s)
		}
	}
	if Severity("nope").Valid() {
		t.Error("nope should be invalid")
	}
}
