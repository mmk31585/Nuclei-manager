package runs

import (
	"context"
	"errors"
	"fmt"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
	"github.com/mmk31585/Nuclei-manager/internal/scope"
)

type Service struct {
	runs     domain.RunRepo
	tasks    domain.TaskRepo
	targets  domain.TargetRepo
	profiles domain.ProfileRepo
	scope    *scope.Service
	wake     chan struct{}
}

func NewService(runs domain.RunRepo, tasks domain.TaskRepo, targets domain.TargetRepo,
	profiles domain.ProfileRepo, sc *scope.Service) *Service {
	return &Service{runs: runs, tasks: tasks, targets: targets, profiles: profiles, scope: sc,
		wake: make(chan struct{}, 1)}
}

// Wake is signalled whenever a run is queued so the worker does not wait for its next poll.
func (s *Service) Wake() <-chan struct{} { return s.wake }

func missing(err error, what string) error {
	if errors.Is(err, domain.ErrNotFound) {
		return fmt.Errorf("%w: %s no longer exists", domain.ErrConflict, what)
	}
	return err
}

// Create validates, snapshots and queues a run for a task.
func (s *Service) Create(ctx context.Context, taskID uint, trigger string) (*domain.Run, error) {
	task, err := s.tasks.Get(ctx, taskID)
	if err != nil {
		return nil, err
	}
	target, err := s.targets.Get(ctx, task.TargetID)
	if err != nil {
		return nil, missing(err, "the task's target")
	}
	profile, err := s.profiles.Get(ctx, task.ProfileID)
	if err != nil {
		return nil, missing(err, "the task's profile")
	}
	if _, err := domain.EffectiveSeverities(profile.Severity, task.MinSeverity); err != nil {
		return nil, err
	}
	if err := s.scope.CheckAll(ctx, target.Hosts); err != nil {
		return nil, err
	}
	raw, err := domain.ConfigSnapshot{Task: *task, Target: *target, Profile: *profile}.Encode()
	if err != nil {
		return nil, err
	}
	run := &domain.Run{TaskID: task.ID, Trigger: trigger, ConfigSnapshot: raw}
	if err := s.runs.CreateForTask(ctx, run); err != nil {
		return nil, err
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return run, nil
}
