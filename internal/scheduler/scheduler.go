package scheduler

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/mmk31585/Nuclei-manager/internal/config"
	"github.com/mmk31585/Nuclei-manager/internal/cron"
	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

// RunEnqueuer queues a run for a task. Implemented by runs.Service.
type RunEnqueuer interface {
	Create(ctx context.Context, taskID uint, trigger string) (*domain.Run, error)
}

// Scheduler periodically checks enabled cron tasks and enqueues runs.
type Scheduler struct {
	cfg    config.Config
	tasks  domain.TaskRepo
	runs   RunEnqueuer
	poll   time.Duration
	mu     sync.Mutex
	cancel context.CancelFunc
}

// New creates a scheduler.
func New(cfg config.Config, tasks domain.TaskRepo, runSvc RunEnqueuer) *Scheduler {
	poll := cfg.SchedulerPoll
	if poll <= 0 {
		poll = 30 * time.Second
	}
	return &Scheduler{
		cfg:   cfg,
		tasks: tasks,
		runs:  runSvc,
		poll:  poll,
	}
}

// Start launches the scheduler goroutine.
func (s *Scheduler) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	go s.loop(ctx)
}

// Stop cancels the scheduler.
func (s *Scheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Scheduler) loop(ctx context.Context) {
	ticker := time.NewTicker(s.poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

func (s *Scheduler) tick(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tasks, err := s.tasks.List(ctx)
	if err != nil {
		slog.Error("[sm] scheduler: list tasks failed", "err", err)
		return
	}

	now := time.Now().UTC()
	for i := range tasks {
		t := &tasks[i]
		if !t.Enabled || t.ScheduleType != domain.ScheduleCron || t.CronExpr == "" {
			continue
		}

		loc, err := time.LoadLocation(t.Timezone)
		if err != nil {
			loc = time.UTC
		}
		localNow := now.In(loc)

		sched, err := cron.Parse(t.CronExpr)
		if err != nil {
			slog.Warn("[sm] scheduler: invalid cron expr", "task_id", t.ID, "err", err)
			continue
		}

		// First sighting: compute and store the next fire time.
		if t.NextRunAt == nil {
			next, err := sched.Next(localNow)
			if err != nil {
				slog.Warn("[sm] scheduler: cannot compute next run", "task_id", t.ID, "err", err)
				continue
			}
			t.NextRunAt = &next
			if err := s.tasks.Update(ctx, t); err != nil {
				slog.Warn("[sm] scheduler: update next_run_at failed", "task_id", t.ID, "err", err)
			}
			continue
		}

		if t.NextRunAt.After(localNow) {
			continue
		}

		// Due: enqueue a run.
		slog.Info("[sm] scheduler: firing scheduled run", "task_id", t.ID)
		run, err := s.runs.Create(ctx, t.ID, domain.TriggerSchedule)
		if err != nil {
			slog.Warn("[sm] scheduler: failed to create run", "task_id", t.ID, "err", err)
		} else {
			slog.Info("[sm] scheduler: run queued", "task_id", t.ID, "run_id", run.ID)
			fired := time.Now().UTC()
			t.LastRunAt = &fired
		}

		// Schedule the next fire.
		next, err := sched.Next(localNow)
		if err != nil {
			slog.Warn("[sm] scheduler: cannot compute next run", "task_id", t.ID, "err", err)
			continue
		}
		t.NextRunAt = &next
		if err := s.tasks.Update(ctx, t); err != nil {
			slog.Warn("[sm] scheduler: update next_run_at failed", "task_id", t.ID, "err", err)
		}
	}
}
