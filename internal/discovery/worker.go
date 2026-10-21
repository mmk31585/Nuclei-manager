package discovery

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/mmk31585/Nuclei-manager/internal/config"
	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

// Worker runs discovery in the background with bounded concurrency.
type Worker struct {
	cfg        config.Config
	discoverer Discoverer
	repo       domain.TargetEndpointRepo
	targetRepo domain.TargetRepo
	sem        chan struct{}
	mu         sync.Mutex
}

// NewWorker creates a discovery worker.
func NewWorker(cfg config.Config, discoverer Discoverer, repo domain.TargetEndpointRepo, targetRepo domain.TargetRepo) *Worker {
	maxConc := cfg.DiscoveryMaxConcurrent
	if maxConc < 1 {
		maxConc = 2
	}
	return &Worker{
		cfg:        cfg,
		discoverer: discoverer,
		repo:       repo,
		targetRepo: targetRepo,
		sem:        make(chan struct{}, maxConc),
	}
}

// DiscoverTarget runs discovery for a single target and updates its status.
func (w *Worker) DiscoverTarget(ctx context.Context, targetID uint) {
	slog.Info("[sm] discovery: starting", "target_id", targetID)
	slog.Debug("[sm] discovery: acquiring semaphore", "target_id", targetID)
	w.sem <- struct{}{}
	defer func() {
		slog.Debug("[sm] discovery: releasing semaphore", "target_id", targetID)
		<-w.sem
	}()

	slog.Debug("[sm] discovery: semaphore acquired", "target_id", targetID)
	target, err := w.targetRepo.Get(ctx, targetID)
	if err != nil {
		slog.Error("[sm] discovery: failed to get target", "target_id", targetID, "err", err)
		return
	}
	slog.Debug("[sm] discovery: got target", "target_id", targetID, "hosts", target.Hosts)

	// Set status to running
	target.DiscoveryStatus = "running"
	if err := w.targetRepo.Update(ctx, target); err != nil {
		slog.Error("[sm] discovery: failed to update status", "target_id", targetID, "err", err)
	}

	now := time.Now()
	opts := Options{
		PortScope:   target.PortScope,
		CustomPorts: target.CustomPorts,
		Rate:        w.cfg.DiscoveryRate,
		TimeoutMs:   w.cfg.DiscoveryTimeoutMs,
		ScanType:    w.cfg.NaabuScanType,
		NaabuPath:   w.cfg.NaabuPath,
		HttpxPath:   w.cfg.HttpxPath,
	}

	discoveryCtx, cancel := context.WithTimeout(ctx, w.cfg.DiscoveryTimeout)
	defer cancel()

	slog.Info("[sm] discovery: running naabu", "target_id", targetID, "timeout", w.cfg.DiscoveryTimeout.String())
	endpoints, err := w.discoverer.Discover(discoveryCtx, target.Hosts, opts)
	slog.Info("[sm] discovery: naabu completed", "target_id", targetID, "endpoints", len(endpoints), "err", err)
	if err != nil {
		slog.Error("[sm] discovery: failed", "target_id", targetID, "err", err)
		target.DiscoveryStatus = "failed"
		target.LastDiscoveryError = err.Error()
		target.LastDiscoveryAt = &now
		w.targetRepo.Update(ctx, target)
		return
	}

	// Upsert endpoints
	var eps []domain.TargetEndpoint
	for _, ep := range endpoints {
		eps = append(eps, domain.TargetEndpoint{
			TargetID:    targetID,
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
	if err := w.repo.Upsert(ctx, eps); err != nil {
		slog.Error("[sm] discovery: upsert failed", "target_id", targetID, "err", err)
		target.DiscoveryStatus = "failed"
		target.LastDiscoveryError = err.Error()
		target.LastDiscoveryAt = &now
		w.targetRepo.Update(ctx, target)
		return
	}

	target.DiscoveryStatus = "done"
	target.LastDiscoveryError = ""
	target.LastDiscoveryAt = &now
	w.targetRepo.Update(ctx, target)
	slog.Info("[sm] discovery: completed", "target_id", targetID, "endpoints", len(endpoints))
}
