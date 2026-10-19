package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

func TestDecideStatus(t *testing.T) {
	cases := []struct {
		name       string
		cause      error
		runErr     error
		exitCode   int
		wantStatus domain.RunStatus
		wantMsg    string
	}{
		{"timeout cause", errTimedOut, nil, 0, domain.RunTimedOut, "max duration reached"},
		{"stopped cause", errStopped, nil, 0, domain.RunStopped, "stopped by user"},
		{"shutdown cause", context.Canceled, nil, 0, domain.RunFailed, "interrupted by service shutdown"},
		{"cause + runErr (timeout wins)", errTimedOut, errors.New("some run err"), 3, domain.RunTimedOut, "max duration reached"},
		{"cause + runErr (stopped wins)", errStopped, errors.New("some run err"), 3, domain.RunStopped, "stopped by user"},
		{"nil cause + runErr", nil, errors.New("run error"), 0, domain.RunFailed, "run error"},
		{"nil cause + exit 3", nil, nil, 3, domain.RunFailed, "nuclei exited with code 3"},
		{"nil cause + exit 1", nil, nil, 1, domain.RunFailed, "nuclei exited with code 1"},
		{"nil cause + exit 0", nil, nil, 0, domain.RunCompleted, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotStatus, gotMsg := decideStatus(tc.cause, tc.runErr, tc.exitCode)
			if gotStatus != tc.wantStatus {
				t.Errorf("status = %s, want %s", gotStatus, tc.wantStatus)
			}
			if gotMsg != tc.wantMsg {
				t.Errorf("msg = %q, want %q", gotMsg, tc.wantMsg)
			}
		})
	}
}

func TestResolveCustomSet(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "custom-templates")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// valid dir
	valid := filepath.Join(root, "goodset")
	if err := os.MkdirAll(valid, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	got, err := resolveCustomSet(root, "goodset")
	if err != nil {
		t.Errorf("valid dir: %v", err)
	}
	if got != valid {
		t.Errorf("valid dir path = %q, want %q", got, valid)
	}

	// ../x rejected
	if _, err := resolveCustomSet(root, "../x"); err == nil {
		t.Errorf("../x expected error, got nil")
	}

	// name with slash rejected
	if _, err := resolveCustomSet(root, "a/b"); err == nil {
		t.Errorf("a/b expected error, got nil")
	}

	// symlink inside root pointing outside root rejected
	outside := filepath.Join(tmp, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	symlink := filepath.Join(root, "evil")
	if err := os.Symlink(outside, symlink); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := resolveCustomSet(root, "evil"); err == nil {
		t.Errorf("symlink escape expected error, got nil")
	}

	// missing dir rejected
	if _, err := resolveCustomSet(root, "missing"); err == nil {
		t.Errorf("missing dir expected error, got nil")
	}

	// a file (not dir) rejected
	file := filepath.Join(root, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := resolveCustomSet(root, "afile"); err == nil {
		t.Errorf("file expected error, got nil")
	}
}

func TestNormalizeExclude(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    []string
		wantErr bool
	}{
		{"URL -> host", []string{"https://staging.example.com/x"}, []string{"staging.example.com"}, false},
		{"CIDR stays", []string{"10.0.0.0/24"}, []string{"10.0.0.0/24"}, false},
		{"wildcard rejected", []string{"*.x.com"}, nil, true},
		{"multiple", []string{"https://a.com", "10.0.0.0/24"}, []string{"a.com", "10.0.0.0/24"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeExclude(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if len(got) != len(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
				return
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("got %v, want %v", got, tc.want)
					break
				}
			}
		})
	}
}
