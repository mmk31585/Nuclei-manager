package store

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

type TaskRepo struct{ db *gorm.DB }

func NewTaskRepo(db *gorm.DB) *TaskRepo { return &TaskRepo{db: db} }

func (r *TaskRepo) Create(ctx context.Context, t *domain.Task) error {
	return mapErr(r.db.WithContext(ctx).Create(t).Error)
}

func (r *TaskRepo) Get(ctx context.Context, id uint) (*domain.Task, error) {
	var t domain.Task
	if err := r.db.WithContext(ctx).First(&t, id).Error; err != nil {
		return nil, mapErr(err)
	}
	return &t, nil
}

func (r *TaskRepo) List(ctx context.Context) ([]domain.Task, error) {
	out := []domain.Task{}
	if err := r.db.WithContext(ctx).Order("id").Find(&out).Error; err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (r *TaskRepo) Update(ctx context.Context, t *domain.Task) error {
	return mapErr(r.db.WithContext(ctx).Save(t).Error)
}

func (r *TaskRepo) Delete(ctx context.Context, id uint) error {
	var active int64
	if err := r.db.WithContext(ctx).Model(&domain.Run{}).
		Where("task_id = ? AND status IN ?", id, []domain.RunStatus{domain.RunQueued, domain.RunRunning}).
		Count(&active).Error; err != nil {
		return err
	}
	if active > 0 {
		return fmt.Errorf("%w: task has an active run", domain.ErrConflict)
	}
	res := r.db.WithContext(ctx).Delete(&domain.Task{}, id)
	if res.Error != nil {
		return mapErr(res.Error)
	}
	if res.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}
