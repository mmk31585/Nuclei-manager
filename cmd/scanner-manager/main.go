package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/mmk31585/Nuclei-manager/internal/api"
	"github.com/mmk31585/Nuclei-manager/internal/config"
	"github.com/mmk31585/Nuclei-manager/internal/runs"
	"github.com/mmk31585/Nuclei-manager/internal/scanner/nuclei"
	"github.com/mmk31585/Nuclei-manager/internal/scope"
	"github.com/mmk31585/Nuclei-manager/internal/store"
	"github.com/mmk31585/Nuclei-manager/internal/worker"
)

// @title                      scanner-manager API
// @version                    0.1
// @description                REST API for managing Nuclei vulnerability scans.
// @description                The service validates every target against a configurable scope allowlist,
// @description                exposes scan profiles (built-in and custom), and stores tasks that bind a
// @description                target to a profile. It is the control plane for a planned worker that
// @description                executes Nuclei and stores runs and findings.
// @termsOfService             http://swagger.io/terms/
// @contact.name               scanner-manager
// @contact.url                https://github.com/mmk31585/Nuclei-manager
// @license.name               MIT
// @license.url                https://opensource.org/licenses/MIT
// @host                       localhost
// @BasePath                   /api/v1
// @schemes                    http
// @accept                     json
// @produce                    json
// @tag.name                   scope
// @tag.description            Scope allowlist entries (domains, CIDRs and IPs) that targets are checked against.
// @tag.name                   targets
// @tag.description            Targets whose hosts are validated against the scope allowlist.
// @tag.name                   profiles
// @tag.description            Nuclei scan profiles, including seeded built-in profiles.
// @tag.name                   tasks
// @tag.description            Tasks that bind a target to a profile.
// @tag.name                   runs
// @tag.description            Runs queued by a task and executed by the worker, including logs and raw output.
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	gin.SetMode(cfg.GinMode)

	for _, d := range []string{cfg.DataDir, filepath.Join(cfg.DataDir, "runs"), cfg.CustomTemplatesDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create dir %s: %w", d, err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	probeCtx, cancelProbe := context.WithTimeout(ctx, 90*time.Second)
	info, err := nuclei.Probe(probeCtx, cfg.NucleiBin)
	cancelProbe()
	if err != nil {
		return err
	}
	slog.Info("nuclei found", "path", info.Path, "version", info.Version, "templates_version", info.TemplatesVersion)

	st, err := store.Open(cfg.DBDSN)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(); err != nil {
		return err
	}
	if err := st.SeedBuiltinProfiles(ctx); err != nil {
		return err
	}
	n, err := st.Runs.RecoverInterrupted(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		slog.Warn("marked interrupted runs as failed", "count", n)
	}

	scopeSvc := scope.NewService(st.Scope)
	runSvc := runs.NewService(st.Runs, st.Tasks, st.Targets, st.Profiles, scopeSvc)
	wk := worker.New(worker.Config{
		DataDir:            cfg.DataDir,
		CustomTemplatesDir: cfg.CustomTemplatesDir,
		MaxConcurrent:      cfg.MaxConcurrentRuns,
		Poll:               cfg.WorkerPoll,
		Nuclei:             info,
	}, st.Runs, scopeSvc, &nuclei.Runner{Bin: info.Path}, runSvc.Wake())
	wk.Start(ctx)

	router := api.NewRouter(api.Deps{
		Ping:            st.Ping,
		Scope:           scopeSvc,
		ScopeRepo:       st.Scope,
		Targets:         st.Targets,
		Profiles:        st.Profiles,
		Tasks:           st.Tasks,
		Runs:            runSvc,
		RunRepo:         st.Runs,
		Stopper:         wk,
		DataDir:         cfg.DataDir,
		SwaggerHost:     cfg.SwaggerHost,
		SwaggerBasePath: cfg.SwaggerBasePath,
	})
	srv := &http.Server{Addr: cfg.HTTPAddr, Handler: router, ReadHeaderTimeout: 10 * time.Second}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", cfg.HTTPAddr)
		errCh <- srv.ListenAndServe()
	}()

	var srvErr error
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			srvErr = err
		}
		stop()
	case <-ctx.Done():
		slog.Info("shutting down")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && srvErr == nil {
		srvErr = err
	}
	wk.Wait() // running scans are stopped by ctx cancellation and finalized in the DB before we close it
	return srvErr
}
