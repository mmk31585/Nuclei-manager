package store

import (
	"context"

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
	res := r.db.WithContext(ctx).Delete(&domain.Task{}, id)
	if res.Error != nil {
		return mapErr(res.Error)
	}
	if res.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}
