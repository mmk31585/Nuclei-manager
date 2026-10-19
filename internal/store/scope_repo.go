package store

import (
	"context"

	"gorm.io/gorm"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

type ScopeRepo struct{ db *gorm.DB }

func NewScopeRepo(db *gorm.DB) *ScopeRepo { return &ScopeRepo{db: db} }

func (r *ScopeRepo) Create(ctx context.Context, e *domain.ScopeEntry) error {
	return mapErr(r.db.WithContext(ctx).Create(e).Error)
}

func (r *ScopeRepo) List(ctx context.Context) ([]domain.ScopeEntry, error) {
	out := []domain.ScopeEntry{}
	if err := r.db.WithContext(ctx).Order("id").Find(&out).Error; err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (r *ScopeRepo) Delete(ctx context.Context, id uint) error {
	res := r.db.WithContext(ctx).Delete(&domain.ScopeEntry{}, id)
	if res.Error != nil {
		return mapErr(res.Error)
	}
	if res.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}
