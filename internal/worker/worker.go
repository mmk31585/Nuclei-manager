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

	"github.com/mmk31585/Nuclei-manager/internal/discovery"
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
	DataDir            string
	CustomTemplatesDir string
	NucleiTemplatesDir string
	MaxConcurrent      int
	Poll               time.Duration
	Nuclei             nuclei.Info
	Discovery          discovery.Discoverer
	DiscoveryOpts      discovery.Options
	DiscoveryTimeout   time.Duration
	TargetEndpoints    domain.TargetEndpointRepo
	Targets            domain.TargetRepo
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
	webArgs          []string
	networkArgs      []string
	networkTargets   string
	scanNetworkPorts bool
	timeout          time.Duration
	exec             domain.RunExecution
	files            targetFiles
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
	appendLog(prep.exec.LogPath, "targets.txt: %d lines (%d original, %d web URLs)",
		len(prep.files.Web), prep.files.Original, len(prep.files.Web)-prep.files.Original)
	appendLog(prep.exec.LogPath, "network_targets.txt: %d lines", len(prep.files.Network))

	var allCounters nuclei.Counters
	var finalStatus domain.RunStatus
	var finalMsg string
	var finalExit int

	// First pass: web targets
	w.setStage(run.ID, domain.RunStageWeb)
	appendLog(prep.exec.LogPath, "nuclei web: starting: %s", prep.exec.CommandLine)

	execCtx, cancelT := context.WithTimeoutCause(runCtx, prep.timeout, errTimedOut)
	defer cancelT()
	res, runErr := w.runner.Run(execCtx, nuclei.RunSpec{
		Args:       prep.webArgs,
		RawOutPath: prep.exec.RawOutputPath,
		LogPath:    prep.exec.LogPath,
		OnProgress: func(c nuclei.Counters) { w.progress(run.ID, c) },
	})
	cause := context.Cause(execCtx) // read BEFORE any cancel() of execCtx
	status, msg := decideStatus(cause, runErr, res.ExitCode)
	appendLog(prep.exec.LogPath, "nuclei web: finished: status=%s exit_code=%d %s", status, res.ExitCode, msg)
	allCounters = nuclei.Counters{
		Total:       res.Counters.Total,
		Critical:    res.Counters.Critical,
		High:        res.Counters.High,
		Medium:      res.Counters.Medium,
		Low:         res.Counters.Low,
		Info:        res.Counters.Info,
		ParseErrors: res.Counters.ParseErrors,
	}
	finalStatus = status
	finalMsg = msg
	finalExit = res.ExitCode

	// Second pass: network ports (if enabled and network targets exist)
	if prep.scanNetworkPorts && len(prep.networkArgs) > 0 && len(prep.files.Network) > 0 {
		networkLogPath := filepath.Join(filepath.Dir(prep.exec.LogPath), "network.log")
		networkOutPath := filepath.Join(filepath.Dir(prep.exec.RawOutputPath), "network.jsonl")
		networkCmdLine := strings.Join(append([]string{w.cfg.Nuclei.Path}, prep.networkArgs...), " ")

		w.setStage(run.ID, domain.RunStageNetwork)
		appendLog(prep.exec.LogPath, "nuclei network: starting: %s", networkCmdLine)

		execCtx2, cancelT2 := context.WithTimeoutCause(runCtx, prep.timeout, errTimedOut)
		defer cancelT2()
		res2, runErr2 := w.runner.Run(execCtx2, nuclei.RunSpec{
			Args:       prep.networkArgs,
			RawOutPath: networkOutPath,
			LogPath:    networkLogPath,
			OnProgress: func(c nuclei.Counters) {
				w.progress(run.ID, mergeCounters(allCounters, c))
			},
		})
		cause2 := context.Cause(execCtx2)
		status2, msg2 := decideStatus(cause2, runErr2, res2.ExitCode)
		appendLog(prep.exec.LogPath, "nuclei network: finished: status=%s exit_code=%d %s", status2, res2.ExitCode, msg2)

		// Merge findings
		allCounters = mergeCounters(allCounters, res2.Counters)

		// If network pass failed worse, use that status
		if status2 == domain.RunFailed || status2 == domain.RunTimedOut {
			if finalStatus == domain.RunCompleted {
				finalStatus = status2
				finalMsg = msg2
				finalExit = res2.ExitCode
			}
		}
	}
	w.setStage(run.ID, domain.RunStageDone)

	log.Info("run finished", "status", finalStatus, "exit_code", finalExit, "results", allCounters.Total)
	w.finish(run.ID, domain.RunFinish{
		Status: finalStatus, ExitCode: &finalExit, ErrorMessage: finalMsg, Counters: toCounters(allCounters),
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
	networkTargetsPath := filepath.Join(dir, "network_targets.txt")

	// Discovery: re-check ports before every run (unless skip_discovery is set)
	var endpoints []domain.TargetEndpoint
	if !snap.Task.SkipDiscovery && w.cfg.Discovery != nil {
		endpoints = w.discoverEndpoints(ctx, snap, dir)
	}

	// Split the endpoints into the two nuclei input files. The scope allowlist
	// is applied again here: it may have changed since the run was queued.
	files := buildTargetFiles(snap.Target.Hosts, endpoints, func(host string) bool {
		return w.scope.IsAllowed(ctx, host)
	})
	if len(files.Web) == 0 {
		return nil, fmt.Errorf("no target left after applying the scope allowlist")
	}

	if err := os.WriteFile(targetsPath, []byte(strings.Join(files.Web, "\n")+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write targets file: %w", err)
	}
	if err := os.WriteFile(networkTargetsPath, []byte(strings.Join(files.Network, "\n")+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write network targets file: %w", err)
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
	} else if w.cfg.NucleiTemplatesDir != "" {
		// Use official Nuclei templates when no custom set is specified
		paths = []string{w.cfg.NucleiTemplatesDir}
	}
	webArgs, err := nuclei.BuildArgs(nuclei.Options{
		TargetsFile: targetsPath, ExcludeHosts: exclude, TemplatePaths: paths,
		TemplateIDs: p.TemplateIDs, Tags: p.Tags, ExcludeTags: p.ExcludeTags,
		Severities: severities, Protocols: p.Protocols,
		RateLimit: p.RateLimit, Concurrency: p.Concurrency, BulkSize: p.BulkSize,
		TimeoutSec: p.TimeoutSec, Retries: p.Retries, MaxHostError: p.MaxHostError,
		NoInteractsh: !p.OAST,
	})
	if err != nil {
		return nil, fmt.Errorf("build nuclei arguments: %w", err)
	}

	// The optional second pass scans the ports that are not web services with
	// the network templates. It only runs when the task asks for it and there
	// is at least one such port.
	var networkArgs []string
	if snap.Task.ScanNetworkPorts && len(files.Network) > 0 {
		protocols := []string(snap.Task.NetworkProtocols)
		if len(protocols) == 0 {
			protocols = []string{"tcp", "javascript"}
		}
		networkArgs, err = nuclei.BuildArgs(nuclei.Options{
			TargetsFile: networkTargetsPath, ExcludeHosts: exclude, TemplatePaths: paths,
			TemplateIDs: p.TemplateIDs, Tags: p.Tags, ExcludeTags: p.ExcludeTags,
			Severities: severities, Protocols: protocols,
			RateLimit: p.RateLimit, Concurrency: p.Concurrency, BulkSize: p.BulkSize,
			TimeoutSec: p.TimeoutSec, Retries: p.Retries, MaxHostError: p.MaxHostError,
			NoInteractsh: !p.OAST,
		})
		if err != nil {
			return nil, fmt.Errorf("build nuclei network arguments: %w", err)
		}
	}

	timeout := time.Duration(p.MaxDurationMin) * time.Minute
	if timeout <= 0 {
		timeout = 120 * time.Minute
	}
	return &prepared{
		webArgs:          webArgs,
		networkArgs:      networkArgs,
		networkTargets:   networkTargetsPath,
		scanNetworkPorts: snap.Task.ScanNetworkPorts,
		timeout:          timeout,
		files:            files,
		exec: domain.RunExecution{
			CommandLine:      strings.Join(append([]string{w.cfg.Nuclei.Path}, webArgs...), " "),
			NucleiVersion:    w.cfg.Nuclei.Version,
			TemplatesVersion: w.cfg.Nuclei.TemplatesVersion,
			LogPath:          filepath.Join(dir, "run.log"),
			RawOutputPath:    filepath.Join(dir, "output.jsonl"),
			TargetsCount:     len(files.Web),
		},
	}, nil
}

// discoverEndpoints runs the port discovery for every host of the target and
// returns the endpoints it found. The endpoints are stored so the next run
// can fall back on them.
func (w *Worker) discoverEndpoints(ctx context.Context, snap domain.ConfigSnapshot, dir string) []domain.TargetEndpoint {
	appendLog(filepath.Join(dir, "run.log"), "discovery: starting")
	slog.Info("discovery: starting", "target_id", snap.Target.ID)

	// Use a timeout for discovery separate from the scan timeout. The deadline
	// comes from the discovery timeout; DiscoveryOpts.TimeoutMs is naabu's
	// per-connection timeout and must not be used as the overall deadline.
	discoveryTimeout := w.cfg.DiscoveryTimeout
	if discoveryTimeout <= 0 {
		discoveryTimeout = 5 * time.Minute
	}
	discoveryCtx, cancelDiscovery := context.WithTimeout(ctx, discoveryTimeout)
	defer cancelDiscovery()

	hosts := snap.Target.Hosts
	var allEndpoints []domain.TargetEndpoint

	// Run discovery for each host
	discoveryFailed := false
	for _, host := range hosts {
		opts := w.cfg.DiscoveryOpts
		opts.PortScope = snap.Target.PortScope
		opts.CustomPorts = snap.Target.CustomPorts
		eps, err := w.cfg.Discovery.Discover(discoveryCtx, []string{host}, opts)
		if err != nil {
			slog.Warn("discovery: failed for host", "host", host, "err", err)
			discoveryFailed = true
			// Fall back to stored endpoints
			stored, _ := w.cfg.TargetEndpoints.ListByTarget(ctx, snap.Target.ID)
			allEndpoints = append(allEndpoints, stored...)
			continue
		}
		// Upsert endpoints
		var upsertEps []domain.TargetEndpoint
		now := time.Now()
		for _, ep := range eps {
			upsertEps = append(upsertEps, domain.TargetEndpoint{
				TargetID:    snap.Target.ID,
				Host:        ep.Host,
				Port:        ep.Port,
				Scheme:      ep.Scheme,
				URL:         ep.URL,
				IsWeb:       ep.IsWeb,
				Source:      ep.Source,
				FirstSeenAt: now,
				LastSeenAt:  now,
			})
		}
		if err := w.cfg.TargetEndpoints.Upsert(ctx, upsertEps); err != nil {
			slog.Warn("discovery: upsert failed", "err", err)
		}
		allEndpoints = append(allEndpoints, upsertEps...)
	}

	// If discovery failed for all hosts, fall back to stored endpoints
	if discoveryFailed {
		stored, _ := w.cfg.TargetEndpoints.ListByTarget(ctx, snap.Target.ID)
		if len(stored) > 0 {
			allEndpoints = stored
		}
	}

	webCount := 0
	for _, ep := range allEndpoints {
		if ep.IsWeb {
			webCount++
		}
	}
	slog.Info("discovery: completed", "target_id", snap.Target.ID,
		"hosts", len(hosts), "open_ports", len(allEndpoints), "web_endpoints", webCount)
	appendLog(filepath.Join(dir, "run.log"), "discovery: %d hosts, %d open ports, %d web endpoints",
		len(hosts), len(allEndpoints), webCount)
	return allEndpoints
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

// mergeCounters adds the counters of a second pass to the ones of the first.
func mergeCounters(a, b nuclei.Counters) nuclei.Counters {
	return nuclei.Counters{
		Total:       a.Total + b.Total,
		Critical:    a.Critical + b.Critical,
		High:        a.High + b.High,
		Medium:      a.Medium + b.Medium,
		Low:         a.Low + b.Low,
		Info:        a.Info + b.Info,
		ParseErrors: a.ParseErrors + b.ParseErrors,
	}
}

// setStage records the pass that is currently executing.
func (w *Worker) setStage(id uint, stage string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.runs.SetStage(ctx, id, stage); err != nil {
		slog.Warn("stage update failed", "run_id", id, "stage", stage, "err", err)
	}
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
