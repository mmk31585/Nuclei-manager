package store

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

type ProfileRepo struct{ db *gorm.DB }

func NewProfileRepo(db *gorm.DB) *ProfileRepo { return &ProfileRepo{db: db} }

func (r *ProfileRepo) Create(ctx context.Context, p *domain.Profile) error {
	return mapErr(r.db.WithContext(ctx).Create(p).Error)
}

func (r *ProfileRepo) Get(ctx context.Context, id uint) (*domain.Profile, error) {
	var p domain.Profile
	if err := r.db.WithContext(ctx).First(&p, id).Error; err != nil {
		return nil, mapErr(err)
	}
	return &p, nil
}

func (r *ProfileRepo) List(ctx context.Context) ([]domain.Profile, error) {
	out := []domain.Profile{}
	if err := r.db.WithContext(ctx).Order("id").Find(&out).Error; err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (r *ProfileRepo) Update(ctx context.Context, p *domain.Profile) error {
	var existing domain.Profile
	if err := r.db.WithContext(ctx).First(&existing, p.ID).Error; err != nil {
		return mapErr(err)
	}
	if existing.Builtin {
		return fmt.Errorf("%w: built-in profiles are read-only", domain.ErrConflict)
	}
	return mapErr(r.db.WithContext(ctx).Save(p).Error)
}

func (r *ProfileRepo) Delete(ctx context.Context, id uint) error {
	var p domain.Profile
	if err := r.db.WithContext(ctx).First(&p, id).Error; err != nil {
		return mapErr(err)
	}
	if p.Builtin {
		return fmt.Errorf("%w: built-in profiles are read-only", domain.ErrConflict)
	}
	var n int64
	if err := r.db.WithContext(ctx).Model(&domain.Task{}).Where("profile_id = ?", id).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: profile is used by %d task(s)", domain.ErrConflict, n)
	}
	res := r.db.WithContext(ctx).Delete(&domain.Profile{}, id)
	if res.Error != nil {
		return mapErr(res.Error)
	}
	if res.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}
