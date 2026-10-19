package store

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

type TargetRepo struct{ db *gorm.DB }

func NewTargetRepo(db *gorm.DB) *TargetRepo { return &TargetRepo{db: db} }

func (r *TargetRepo) Create(ctx context.Context, t *domain.Target) error {
	return mapErr(r.db.WithContext(ctx).Create(t).Error)
}

func (r *TargetRepo) Get(ctx context.Context, id uint) (*domain.Target, error) {
	var t domain.Target
	if err := r.db.WithContext(ctx).First(&t, id).Error; err != nil {
		return nil, mapErr(err)
	}
	return &t, nil
}

func (r *TargetRepo) List(ctx context.Context) ([]domain.Target, error) {
	out := []domain.Target{}
	if err := r.db.WithContext(ctx).Order("id").Find(&out).Error; err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (r *TargetRepo) Update(ctx context.Context, t *domain.Target) error {
	return mapErr(r.db.WithContext(ctx).Save(t).Error)
}

func (r *TargetRepo) Delete(ctx context.Context, id uint) error {
	var n int64
	if err := r.db.WithContext(ctx).Model(&domain.Task{}).Where("target_id = ?", id).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: target is used by %d task(s)", domain.ErrConflict, n)
	}
	res := r.db.WithContext(ctx).Delete(&domain.Target{}, id)
	if res.Error != nil {
		return mapErr(res.Error)
	}
	if res.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}
