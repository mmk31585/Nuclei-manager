package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Runner struct {
	Bin          string
	ExtraEnv     []string      // tests only
	GracePeriod  time.Duration // SIGTERM -> forced kill; default 10s
	MaxLineBytes int           // longer stdout lines are dropped; default 16 MiB
}

type RunSpec struct {
	Args       []string
	RawOutPath string // valid result events, one JSON per line
	LogPath    string // stderr + supervisor lines (appended)
	OnProgress func(Counters)
}

type RunResult struct {
	ExitCode int // -1 if the process did not start or was killed by a signal
	Counters Counters
}

// childEnv hides this service's own configuration (SM_*, e.g. the DB DSN) from the scanner process.
func childEnv(extra []string) []string {
	env := make([]string, 0, 32)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "SM_") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

// lineWriter splits a byte stream into lines and drops lines longer than max.
type lineWriter struct {
	mu         sync.Mutex
	buf        []byte
	max        int
	skipping   bool
	onLine     func([]byte) // must not retain the slice
	onOverflow func()
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if !w.skipping {
				if len(w.buf)+len(p) > w.max {
					w.buf = w.buf[:0]
					w.skipping = true
					w.onOverflow()
				} else {
					w.buf = append(w.buf, p...)
				}
			}
			break
		}
		chunk := p[:i]
		p = p[i+1:]
		switch {
		case w.skipping:
			w.skipping = false // the oversized line ends here
		case len(w.buf)+len(chunk) > w.max:
			w.buf = w.buf[:0]
			w.onOverflow()
		case len(w.buf) == 0:
			w.onLine(chunk)
		default:
			w.buf = append(w.buf, chunk...)
			w.onLine(w.buf)
			w.buf = w.buf[:0]
		}
	}
	return n, nil
}

func (w *lineWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.skipping && len(w.buf) > 0 {
		w.onLine(w.buf)
	}
	w.buf = w.buf[:0]
}

func (r *Runner) Run(ctx context.Context, spec RunSpec) (RunResult, error) {
	res := RunResult{ExitCode: -1}
	grace := r.GracePeriod
	if grace <= 0 {
		grace = 10 * time.Second
	}
	maxLine := r.MaxLineBytes
	if maxLine <= 0 {
		maxLine = 16 << 20
	}

	rawFile, err := os.OpenFile(spec.RawOutPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return res, fmt.Errorf("open raw output: %w", err)
	}
	defer rawFile.Close()
	logFile, err := os.OpenFile(spec.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return res, fmt.Errorf("open log: %w", err)
	}
	defer logFile.Close()

	raw := bufio.NewWriterSize(rawFile, 64<<10)
	var (
		cmu          sync.Mutex
		counters     Counters
		lastProgress = time.Now()
	)
	handle := func(line []byte) {
		t := bytes.TrimSpace(line)
		if len(t) == 0 {
			return
		}
		cmu.Lock()
		defer cmu.Unlock()
		if t[0] != '{' {
			fmt.Fprintf(logFile, "[stdout] %.500s\n", t)
			return
		}
		ev, err := ParseLine(t)
		if err != nil {
			counters.ParseErrors++
			fmt.Fprintf(logFile, "[sm] unparsable stdout line: %.200s\n", t)
			return
		}
		raw.Write(t)
		raw.WriteByte('\n')
		counters.Add(ev)
		if spec.OnProgress != nil && time.Since(lastProgress) >= 5*time.Second {
			lastProgress = time.Now()
			raw.Flush()
			spec.OnProgress(counters)
		}
	}
	lw := &lineWriter{
		max:    maxLine,
		onLine: handle,
		onOverflow: func() {
			cmu.Lock()
			counters.ParseErrors++
			fmt.Fprintln(logFile, "[sm] dropped an oversized stdout line")
			cmu.Unlock()
		},
	}

	cmd := exec.CommandContext(ctx, r.Bin, spec.Args...)
	cmd.Env = childEnv(r.ExtraEnv)
	cmd.Stdout = lw // not an *os.File: exec copies it in a goroutine and WaitDelay bounds that wait
	cmd.Stderr = logFile
	setProcAttr(cmd)
	cmd.Cancel = func() error { return killGroup(cmd, syscall.SIGTERM) }
	cmd.WaitDelay = grace

	if err := cmd.Start(); err != nil {
		return res, fmt.Errorf("start nuclei: %w", err)
	}
	waitErr := cmd.Wait()
	_ = killGroup(cmd, syscall.SIGKILL) // reap anything still alive in the process group

	lw.Flush()
	cmu.Lock()
	if err := raw.Flush(); err != nil && waitErr == nil {
		waitErr = fmt.Errorf("write raw output: %w", err)
	}
	res.Counters = counters
	cmu.Unlock()
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	return res, waitErr
}
