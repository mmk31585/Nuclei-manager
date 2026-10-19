//go:build linux

package nuclei

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func stubPath(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("testdata/fake-nuclei.sh")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode()&0o111 == 0 {
		t.Fatalf("stub not executable: %v", err)
	}
	return p
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("file %s did not appear within %v", path, timeout)
}

func readPid(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pid %s: %v", path, err)
	}
	pid := 0
	fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid)
	return pid
}

func eventually(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

func processAlive(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return false
	}
	return s[i+2] != 'Z'
}

func TestRunnerOK(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{
		Bin:      stubPath(t),
		ExtraEnv: []string{"FAKE_MODE=ok"},
	}
	ctx := context.Background()
	res, err := r.Run(ctx, RunSpec{
		Args:       []string{"-list", "x"},
		RawOutPath: filepath.Join(dir, "output.jsonl"),
		LogPath:    filepath.Join(dir, "run.log"),
	})
	if err != nil {
		t.Fatalf("Run = err %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.ExitCode)
	}
	if res.Counters.Total != 3 || res.Counters.Critical != 1 || res.Counters.Medium != 1 ||
		res.Counters.Info != 1 || res.Counters.ParseErrors != 1 {
		t.Errorf("counters = %+v", res.Counters)
	}
	// output.jsonl has exactly 3 lines
	b, _ := os.ReadFile(filepath.Join(dir, "output.jsonl"))
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 3 {
		t.Errorf("output.jsonl has %d lines, want 3", len(lines))
	}
	// log contains [INF] and [stdout]
	logB, _ := os.ReadFile(filepath.Join(dir, "run.log"))
	log := string(logB)
	if !strings.Contains(log, "[INF] some log line") {
		t.Errorf("log missing [INF] line")
	}
	if !strings.Contains(log, "[stdout] this is not json") {
		t.Errorf("log missing [stdout] non-json line")
	}
}

func TestRunnerExit3(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{
		Bin:      stubPath(t),
		ExtraEnv: []string{"FAKE_MODE=exit3"},
	}
	ctx := context.Background()
	res, err := r.Run(ctx, RunSpec{
		Args:       []string{"-list", "x"},
		RawOutPath: filepath.Join(dir, "output.jsonl"),
		LogPath:    filepath.Join(dir, "run.log"),
	})
	if err == nil {
		t.Log("Run returned no error, checking ExitCode")
	}
	if res.ExitCode != 3 {
		t.Errorf("exit code = %d, want 3", res.ExitCode)
	}
	if res.Counters.Total != 1 {
		t.Errorf("total = %d, want 1", res.Counters.Total)
	}
}

func TestRunnerBigLine(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{
		Bin:          stubPath(t),
		MaxLineBytes: 1 << 20, // 1 MiB, the 3 MiB line will be dropped
		ExtraEnv:     []string{"FAKE_MODE=big"},
	}
	ctx := context.Background()
	res, err := r.Run(ctx, RunSpec{
		Args:       []string{"-list", "x"},
		RawOutPath: filepath.Join(dir, "output.jsonl"),
		LogPath:    filepath.Join(dir, "run.log"),
	})
	if err != nil {
		t.Fatalf("Run = err %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.ExitCode)
	}
	if res.Counters.Total != 1 || res.Counters.High != 1 || res.Counters.ParseErrors != 1 {
		t.Errorf("counters = %+v", res.Counters)
	}
}

func TestRunnerCancelKillsWholeProcessGroup(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pid")
	r := &Runner{
		Bin:         stubPath(t),
		GracePeriod: 500 * time.Millisecond,
		ExtraEnv:    []string{"FAKE_MODE=hang", "FAKE_PIDFILE=" + pidFile},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r.Run(ctx, RunSpec{
			Args:       []string{"-list", "x"},
			RawOutPath: filepath.Join(dir, "output.jsonl"),
			LogPath:    filepath.Join(dir, "run.log"),
		})
	}()

	waitForFile(t, pidFile, 5*time.Second)
	cancel()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	for _, p := range []string{pidFile, pidFile + ".main"} {
		pid := readPid(t, p)
		eventually(t, 3*time.Second, func() bool { return !processAlive(pid) })
	}
}
