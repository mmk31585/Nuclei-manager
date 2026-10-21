package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

type RunRepo struct{ db *gorm.DB }

func NewRunRepo(db *gorm.DB) *RunRepo { return &RunRepo{db: db} }

func (r *RunRepo) CreateForTask(ctx context.Context, run *domain.Run) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Lock the task row so two concurrent requests cannot both pass the check below.
		var task domain.Task
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&task, run.TaskID).Error; err != nil {
			return mapErr(err)
		}
		var active int64
		if err := tx.Model(&domain.Run{}).
			Where("task_id = ? AND status IN ?", run.TaskID, []domain.RunStatus{domain.RunQueued, domain.RunRunning}).
			Count(&active).Error; err != nil {
			return err
		}
		if active > 0 {
			return fmt.Errorf("%w: task already has an active run", domain.ErrConflict)
		}
		run.Status = domain.RunQueued
		return mapErr(tx.Create(run).Error)
	})
}

func (r *RunRepo) Get(ctx context.Context, id uint) (*domain.Run, error) {
	var run domain.Run
	if err := r.db.WithContext(ctx).First(&run, id).Error; err != nil {
		return nil, mapErr(err)
	}
	return &run, nil
}

func (r *RunRepo) List(ctx context.Context, f domain.RunFilter) ([]domain.Run, error) {
	q := r.db.WithContext(ctx).Omit("config_snapshot").Order("id DESC")
	if f.TaskID != 0 {
		q = q.Where("task_id = ?", f.TaskID)
	}
	if f.Status != "" {
		q = q.Where("status = ?", f.Status)
	}
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	out := []domain.Run{}
	if err := q.Limit(limit).Find(&out).Error; err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (r *RunRepo) ClaimNext(ctx context.Context) (*domain.Run, error) {
	var claimed *domain.Run
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var run domain.Run
		err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("status = ?", domain.RunQueued).Order("id").Limit(1).Take(&run).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		if err := tx.Model(&domain.Run{}).Where("id = ?", run.ID).
			Updates(map[string]any{"status": domain.RunRunning, "started_at": now}).Error; err != nil {
			return err
		}
		run.Status = domain.RunRunning
		run.StartedAt = &now
		claimed = &run
		return nil
	})
	return claimed, err
}

func counterColumns(c domain.RunCounters) map[string]any {
	return map[string]any{
		"results_total":     c.Total,
		"findings_critical": c.Critical,
		"findings_high":     c.High,
		"findings_medium":   c.Medium,
		"findings_low":      c.Low,
		"findings_info":     c.Info,
		"parse_errors":      c.ParseErrors,
	}
}

func (r *RunRepo) SetExecution(ctx context.Context, id uint, e domain.RunExecution) error {
	return r.db.WithContext(ctx).Model(&domain.Run{}).
		Where("id = ? AND status = ?", id, domain.RunRunning).
		Updates(map[string]any{
			"command_line":      e.CommandLine,
			"nuclei_version":    e.NucleiVersion,
			"templates_version": e.TemplatesVersion,
			"log_path":          e.LogPath,
			"raw_output_path":   e.RawOutputPath,
			"targets_count":     e.TargetsCount,
		}).Error
}

func (r *RunRepo) SetStage(ctx context.Context, id uint, stage string) error {
	return r.db.WithContext(ctx).Model(&domain.Run{}).
		Where("id = ? AND status = ?", id, domain.RunRunning).
		Update("stage", stage).Error
}

func (r *RunRepo) UpdateProgress(ctx context.Context, id uint, c domain.RunCounters) error {
	return r.db.WithContext(ctx).Model(&domain.Run{}).
		Where("id = ? AND status = ?", id, domain.RunRunning).
		Updates(counterColumns(c)).Error
}

func (r *RunRepo) Finish(ctx context.Context, id uint, f domain.RunFinish) error {
	cols := counterColumns(f.Counters)
	cols["status"] = f.Status
	cols["finished_at"] = time.Now().UTC()
	cols["exit_code"] = f.ExitCode
	cols["error_message"] = f.ErrorMessage
	return r.db.WithContext(ctx).Model(&domain.Run{}).
		Where("id = ? AND status = ?", id, domain.RunRunning).
		Updates(cols).Error
}

func (r *RunRepo) CancelQueued(ctx context.Context, id uint) (bool, error) {
	res := r.db.WithContext(ctx).Model(&domain.Run{}).
		Where("id = ? AND status = ?", id, domain.RunQueued).
		Updates(map[string]any{
			"status":        domain.RunCancelled,
			"finished_at":   time.Now().UTC(),
			"error_message": "cancelled before start",
		})
	return res.RowsAffected > 0, res.Error
}

func (r *RunRepo) RecoverInterrupted(ctx context.Context) (int64, error) {
	res := r.db.WithContext(ctx).Model(&domain.Run{}).
		Where("status IN ?", []domain.RunStatus{domain.RunRunning, domain.RunProcessing}).
		Updates(map[string]any{
			"status":        domain.RunFailed,
			"finished_at":   time.Now().UTC(),
			"error_message": "interrupted by service restart",
		})
	return res.RowsAffected, res.Error
}
