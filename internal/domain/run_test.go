package domain

import (
	"errors"
	"testing"
)

func TestRunStatusTerminal(t *testing.T) {
	cases := []struct {
		s    RunStatus
		want bool
	}{
		{RunQueued, false},
		{RunRunning, false},
		{RunProcessing, false},
		{RunCompleted, true},
		{RunFailed, true},
		{RunTimedOut, true},
		{RunStopped, true},
		{RunCancelled, true},
		{RunStatus("bogus"), false},
	}
	for _, tc := range cases {
		if got := tc.s.Terminal(); got != tc.want {
			t.Errorf("RunStatus(%q).Terminal() = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestEffectiveSeverities(t *testing.T) {
	cases := []struct {
		profile []string
		floor   Severity
		want    []string
		wantErr bool
	}{
		{[]string{}, SeverityMedium, []string{"medium", "high", "critical"}, false},
		{[]string{"low", "medium"}, SeverityMedium, []string{"medium"}, false},
		{[]string{"low"}, SeverityHigh, nil, true},
		{[]string{"bogus"}, SeverityInfo, nil, true},
		{[]string{"critical"}, SeverityInfo, []string{"critical"}, false},
		{[]string{"info", "low"}, SeverityHigh, nil, true},
	}
	for _, tc := range cases {
		got, err := EffectiveSeverities(tc.profile, tc.floor)
		if tc.wantErr {
			if err == nil || !errors.Is(err, ErrValidation) {
				t.Errorf("EffectiveSeverities(%v, %q) = %v, %v; want ErrValidation", tc.profile, tc.floor, got, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("EffectiveSeverities(%v, %q) unexpected error: %v", tc.profile, tc.floor, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("EffectiveSeverities(%v, %q) = %v, want %v", tc.profile, tc.floor, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("EffectiveSeverities(%v, %q) = %v, want %v", tc.profile, tc.floor, got, tc.want)
				break
			}
		}
	}
}
