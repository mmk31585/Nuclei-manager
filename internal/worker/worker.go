package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
	"github.com/mmk31585/Nuclei-manager/internal/scanner/nuclei"
	"github.com/mmk31585/Nuclei-manager/internal/scope"
)

var (
	errStopped   = errors.New("stopped by user")
	errTimedOut  = errors.New("max duration reached")
	ErrNotActive = errors.New("run is not active on this instance")
)

type Config struct {
	DataDir              string
	CustomTemplatesDir   string
	OfficialTemplatesDir string
	MaxConcurrent        int
	Poll                 time.Duration
	Nuclei               nuclei.Info
}

type Worker struct {
	cfg    Config
	runs   domain.RunRepo
	scope  *scope.Service
	runner *nuclei.Runner
	wake   <-chan struct{}

	mu     sync.Mutex
	active map[uint]context.CancelCauseFunc
	wg     sync.WaitGroup
}

func New(cfg Config, runs domain.RunRepo, sc *scope.Service, runner *nuclei.Runner, wake <-chan struct{}) *Worker {
	return &Worker{cfg: cfg, runs: runs, scope: sc, runner: runner, wake: wake,
		active: make(map[uint]context.CancelCauseFunc)}
}

// Start launches the claim loop. Cancel ctx to shut down, then call Wait.
func (w *Worker) Start(ctx context.Context) {
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.loop(ctx)
	}()
}

// Wait blocks until the loop and every in-flight run have been finalized in the database.
func (w *Worker) Wait() { w.wg.Wait() }

func (w *Worker) Stop(id uint) error {
	w.mu.Lock()
	cancel, ok := w.active[id]
	w.mu.Unlock()
	if !ok {
		return ErrNotActive
	}
	cancel(errStopped)
	return nil
}

func (w *Worker) loop(ctx context.Context) {
	t := time.NewTicker(w.cfg.Poll)
	defer t.Stop()
	sem := make(chan struct{}, w.cfg.MaxConcurrent)
	for {
		w.drain(ctx, sem)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-w.wake:
		}
	}
}

func (w *Worker) drain(ctx context.Context, sem chan struct{}) {
	for {
		select {
		case sem <- struct{}{}:
		default:
			return // all slots busy
		}
		run, err := w.runs.ClaimNext(ctx)
		if err != nil || run == nil {
			<-sem
			if err != nil && ctx.Err() == nil {
				slog.Error("claim run failed", "err", err)
			}
			return
		}
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			defer func() { <-sem }()
			w.execute(ctx, run)
		}()
	}
}

type prepared struct {
	args    []string
	exec    domain.RunExecution
	timeout time.Duration
}

func (w *Worker) execute(appCtx context.Context, run *domain.Run) {
	log := slog.With("run_id", run.ID, "task_id", run.TaskID)
	runCtx, cancel := context.WithCancelCause(appCtx)
	defer cancel(nil)
	w.mu.Lock()
	w.active[run.ID] = cancel
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		delete(w.active, run.ID)
		w.mu.Unlock()
	}()

	prep, err := w.prepare(runCtx, run)
	if err != nil {
		status, msg := domain.RunFailed, err.Error()
		if errors.Is(context.Cause(runCtx), errStopped) {
			status, msg = domain.RunStopped, "stopped by user"
		}
		log.Error("run preparation failed", "err", err)
		w.finish(run.ID, domain.RunFinish{Status: status, ErrorMessage: msg})
		return
	}
	setCtx, setCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := w.runs.SetExecution(setCtx, run.ID, prep.exec); err != nil {
		log.Warn("could not store execution info", "err", err)
	}
	setCancel()
	appendLog(prep.exec.LogPath, "starting: %s", prep.exec.CommandLine)

	execCtx, cancelT := context.WithTimeoutCause(runCtx, prep.timeout, errTimedOut)
	defer cancelT()
	res, runErr := w.runner.Run(execCtx, nuclei.RunSpec{
		Args:       prep.args,
		RawOutPath: prep.exec.RawOutputPath,
		LogPath:    prep.exec.LogPath,
		OnProgress: func(c nuclei.Counters) { w.progress(run.ID, c) },
	})
	cause := context.Cause(execCtx) // read BEFORE any cancel() of execCtx
	status, msg := decideStatus(cause, runErr, res.ExitCode)
	appendLog(prep.exec.LogPath, "finished: status=%s exit_code=%d %s", status, res.ExitCode, msg)
	exit := res.ExitCode
	log.Info("run finished", "status", status, "exit_code", exit, "results", res.Counters.Total)
	w.finish(run.ID, domain.RunFinish{
		Status: status, ExitCode: &exit, ErrorMessage: msg, Counters: toCounters(res.Counters),
	})
}

// decideStatus is pure so it can be tested exhaustively.
func decideStatus(cause, runErr error, exitCode int) (domain.RunStatus, string) {
	switch {
	case errors.Is(cause, errTimedOut):
		return domain.RunTimedOut, "max duration reached"
	case errors.Is(cause, errStopped):
		return domain.RunStopped, "stopped by user"
	case cause != nil:
		return domain.RunFailed, "interrupted by service shutdown"
	case runErr != nil:
		return domain.RunFailed, runErr.Error()
	case exitCode != 0:
		return domain.RunFailed, fmt.Sprintf("nuclei exited with code %d", exitCode)
	default:
		return domain.RunCompleted, ""
	}
}

func (w *Worker) prepare(ctx context.Context, run *domain.Run) (*prepared, error) {
	snap, err := domain.DecodeSnapshot(run.ConfigSnapshot)
	if err != nil {
		return nil, fmt.Errorf("invalid config snapshot: %w", err)
	}
	// Safety: the allowlist may have changed since the run was queued.
	if err := w.scope.CheckAll(ctx, snap.Target.Hosts); err != nil {
		return nil, fmt.Errorf("scope check failed: %w", err)
	}

	dir := filepath.Join(w.cfg.DataDir, "runs", strconv.FormatUint(uint64(run.ID), 10))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create run dir: %w", err)
	}
	targetsPath := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targetsPath, []byte(strings.Join(snap.Target.Hosts, "\n")+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write targets file: %w", err)
	}

	p := snap.Profile
	severities, err := domain.EffectiveSeverities(p.Severity, snap.Task.MinSeverity)
	if err != nil {
		return nil, err
	}
	exclude, err := normalizeExclude(snap.Target.Exclude)
	if err != nil {
		return nil, err
	}
	var paths []string
	if p.CustomSet != "" {
		dirPath, err := resolveCustomSet(w.cfg.CustomTemplatesDir, p.CustomSet)
		if err != nil {
			return nil, err
		}
		paths = []string{dirPath}
	} else if w.cfg.OfficialTemplatesDir != "" {
		// Use official Nuclei templates when no custom set is specified
		paths = []string{w.cfg.OfficialTemplatesDir}
	}
	args, err := nuclei.BuildArgs(nuclei.Options{
		TargetsFile: targetsPath, ExcludeHosts: exclude, TemplatePaths: paths,
		TemplateIDs: p.TemplateIDs, Tags: p.Tags, ExcludeTags: p.ExcludeTags,
		Severities: severities, Protocols: p.Protocols,
		RateLimit: p.RateLimit, Concurrency: p.Concurrency, BulkSize: p.BulkSize,
		TimeoutSec: p.TimeoutSec, Retries: p.Retries, MaxHostError: p.MaxHostError,
		OAST: p.OAST,
	})
	if err != nil {
		return nil, fmt.Errorf("build nuclei arguments: %w", err)
	}
	timeout := time.Duration(p.MaxDurationMin) * time.Minute
	if timeout <= 0 {
		timeout = 120 * time.Minute
	}
	return &prepared{
		args:    args,
		timeout: timeout,
		exec: domain.RunExecution{
			CommandLine:      strings.Join(append([]string{w.cfg.Nuclei.Path}, args...), " "),
			NucleiVersion:    w.cfg.Nuclei.Version,
			TemplatesVersion: w.cfg.Nuclei.TemplatesVersion,
			LogPath:          filepath.Join(dir, "run.log"),
			RawOutputPath:    filepath.Join(dir, "output.jsonl"),
			TargetsCount:     len(snap.Target.Hosts),
		},
	}, nil
}

func normalizeExclude(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if _, err := netip.ParsePrefix(v); err == nil {
			out = append(out, v)
			continue
		}
		h, err := scope.ExtractHost(v)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude entry %q: %w", v, err)
		}
		out = append(out, h) // a URL exclude excludes the whole host (safe direction)
	}
	return out, nil
}

var reSetName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// resolveCustomSet maps a profile's custom_set name to a real directory inside root.
func resolveCustomSet(root, name string) (string, error) {
	if !reSetName.MatchString(name) {
		return "", fmt.Errorf("invalid custom_set name %q", name)
	}
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("custom templates dir: %w", err)
	}
	full, err := filepath.EvalSymlinks(filepath.Join(rootReal, name))
	if err != nil {
		return "", fmt.Errorf("custom_set %q not found", name)
	}
	if !strings.HasPrefix(full, rootReal+string(filepath.Separator)) {
		return "", fmt.Errorf("custom_set %q escapes the templates directory", name)
	}
	if st, err := os.Stat(full); err != nil || !st.IsDir() {
		return "", fmt.Errorf("custom_set %q is not a directory", name)
	}
	return full, nil
}

func toCounters(c nuclei.Counters) domain.RunCounters {
	return domain.RunCounters{Total: c.Total, Critical: c.Critical, High: c.High, Medium: c.Medium,
		Low: c.Low, Info: c.Info, ParseErrors: c.ParseErrors}
}

func (w *Worker) progress(id uint, c nuclei.Counters) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.runs.UpdateProgress(ctx, id, toCounters(c)); err != nil {
		slog.Warn("progress update failed", "run_id", id, "err", err)
	}
}

// finish uses a fresh context: the run context is usually already cancelled here.
func (w *Worker) finish(id uint, f domain.RunFinish) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := w.runs.Finish(ctx, id, f); err != nil {
		slog.Error("failed to finalize run", "run_id", id, "err", err)
	}
}

func appendLog(path, format string, args ...any) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s [sm] %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
}
