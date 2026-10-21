package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/mmk31585/Nuclei-manager/internal/config"
	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

type fakeTaskRepo struct {
	tasks map[uint]*domain.Task
	next  uint
}

func newFakeTaskRepo() *fakeTaskRepo {
	return &fakeTaskRepo{tasks: map[uint]*domain.Task{}, next: 1}
}

func (r *fakeTaskRepo) Create(_ context.Context, t *domain.Task) error {
	t.ID = r.next
	r.next++
	r.tasks[t.ID] = t
	return nil
}

func (r *fakeTaskRepo) Get(_ context.Context, id uint) (*domain.Task, error) {
	t, ok := r.tasks[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return t, nil
}

func (r *fakeTaskRepo) List(_ context.Context) ([]domain.Task, error) {
	out := []domain.Task{}
	for _, t := range r.tasks {
		out = append(out, *t)
	}
	return out, nil
}

func (r *fakeTaskRepo) Update(_ context.Context, t *domain.Task) error {
	r.tasks[t.ID] = t
	return nil
}

func (r *fakeTaskRepo) Delete(_ context.Context, id uint) error {
	delete(r.tasks, id)
	return nil
}

func TestTickComputesNextRunOnFirstSighting(t *testing.T) {
	repo := newFakeTaskRepo()
	repo.tasks[1] = &domain.Task{
		ID:           1,
		Name:         "cron-task",
		Enabled:      true,
		ScheduleType: domain.ScheduleCron,
		CronExpr:     "0 3 * * *",
		Timezone:     "UTC",
	}

	s := &Scheduler{tasks: repo, poll: time.Second}
	s.tick(context.Background())

	task := repo.tasks[1]
	if task.NextRunAt == nil {
		t.Fatal("NextRunAt not set on first tick")
	}
	if task.LastRunAt != nil {
		t.Errorf("LastRunAt = %v, want nil (should not fire yet)", task.LastRunAt)
	}
}

func TestTickSkipsDisabledAndOnceTasks(t *testing.T) {
	repo := newFakeTaskRepo()
	repo.tasks[1] = &domain.Task{
		ID: 1, Name: "disabled", Enabled: false,
		ScheduleType: domain.ScheduleCron, CronExpr: "* * * * *", Timezone: "UTC",
	}
	repo.tasks[2] = &domain.Task{
		ID: 2, Name: "once", Enabled: true,
		ScheduleType: domain.ScheduleOnce, Timezone: "UTC",
	}

	s := &Scheduler{tasks: repo, poll: time.Second}
	s.tick(context.Background())

	if repo.tasks[1].NextRunAt != nil {
		t.Error("disabled task got NextRunAt")
	}
	if repo.tasks[2].NextRunAt != nil {
		t.Error("once task got NextRunAt")
	}
}

func TestTickIgnoresInvalidCron(t *testing.T) {
	repo := newFakeTaskRepo()
	repo.tasks[1] = &domain.Task{
		ID: 1, Name: "bad-cron", Enabled: true,
		ScheduleType: domain.ScheduleCron, CronExpr: "not a cron", Timezone: "UTC",
	}

	s := &Scheduler{tasks: repo, poll: time.Second}
	s.tick(context.Background())

	if repo.tasks[1].NextRunAt != nil {
		t.Error("invalid cron task got NextRunAt")
	}
}

type fakeRunEnqueuer struct {
	created []uint
	err     error
}

func (f *fakeRunEnqueuer) Create(_ context.Context, taskID uint, _ string) (*domain.Run, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.created = append(f.created, taskID)
	return &domain.Run{ID: uint(len(f.created)), TaskID: taskID}, nil
}

func TestTickFiresDueTask(t *testing.T) {
	repo := newFakeTaskRepo()
	past := time.Now().UTC().Add(-time.Hour)
	repo.tasks[1] = &domain.Task{
		ID: 1, Name: "due", Enabled: true,
		ScheduleType: domain.ScheduleCron, CronExpr: "* * * * *", Timezone: "UTC",
		NextRunAt: &past,
	}
	enqueuer := &fakeRunEnqueuer{}

	s := &Scheduler{tasks: repo, runs: enqueuer, poll: time.Second}
	s.tick(context.Background())

	if len(enqueuer.created) != 1 || enqueuer.created[0] != 1 {
		t.Errorf("created = %v, want [1]", enqueuer.created)
	}
	if repo.tasks[1].LastRunAt == nil {
		t.Error("LastRunAt not set after firing")
	}
	if !repo.tasks[1].NextRunAt.After(past) {
		t.Error("NextRunAt not advanced after firing")
	}
}

func TestTickContinuesWhenRunCannotBeCreated(t *testing.T) {
	repo := newFakeTaskRepo()
	past := time.Now().UTC().Add(-time.Hour)
	repo.tasks[1] = &domain.Task{
		ID: 1, Name: "busy", Enabled: true,
		ScheduleType: domain.ScheduleCron, CronExpr: "* * * * *", Timezone: "UTC",
		NextRunAt: &past,
	}
	enqueuer := &fakeRunEnqueuer{err: domain.ErrConflict}

	s := &Scheduler{tasks: repo, runs: enqueuer, poll: time.Second}
	s.tick(context.Background())

	// The schedule must still advance so the task does not spin.
	if !repo.tasks[1].NextRunAt.After(past) {
		t.Error("NextRunAt not advanced after a failed enqueue")
	}
	if repo.tasks[1].LastRunAt != nil {
		t.Error("LastRunAt set even though no run was created")
	}
}

func TestNewDefaultsPoll(t *testing.T) {
	s := New(config.Config{}, newFakeTaskRepo(), nil)
	if s.poll != 30*time.Second {
		t.Errorf("poll = %v, want 30s", s.poll)
	}
}
