package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/mmk31585/Nuclei-manager/internal/api"
	"github.com/mmk31585/Nuclei-manager/internal/config"
	"github.com/mmk31585/Nuclei-manager/internal/scope"
	"github.com/mmk31585/Nuclei-manager/internal/store"
)

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

	st, err := store.Open(cfg.DBDSN)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := st.Migrate(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := st.SeedBuiltinProfiles(ctx); err != nil {
		return err
	}

	router := api.NewRouter(api.Deps{
		Ping:      st.Ping,
		Scope:     scope.NewService(st.Scope),
		ScopeRepo: st.Scope,
		Targets:   st.Targets,
		Profiles:  st.Profiles,
		Tasks:     st.Tasks,
	})
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", cfg.HTTPAddr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		slog.Info("shutting down")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
