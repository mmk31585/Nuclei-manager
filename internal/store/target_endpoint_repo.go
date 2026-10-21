package store

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

type TargetEndpointRepo struct{ db *gorm.DB }

func NewTargetEndpointRepo(db *gorm.DB) *TargetEndpointRepo {
	return &TargetEndpointRepo{db: db}
}

func (r *TargetEndpointRepo) Upsert(ctx context.Context, endpoints []domain.TargetEndpoint) error {
	if len(endpoints) == 0 {
		return nil
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for i := range endpoints {
			var existing domain.TargetEndpoint
			err := tx.Where("target_id = ? AND host = ? AND port = ?", endpoints[i].TargetID, endpoints[i].Host, endpoints[i].Port).First(&existing).Error
			switch err {
			case nil:
				// Update last_seen_at and other fields
				existing.Scheme = endpoints[i].Scheme
				existing.URL = endpoints[i].URL
				existing.IsWeb = endpoints[i].IsWeb
				existing.Source = endpoints[i].Source
				existing.LastSeenAt = endpoints[i].LastSeenAt
				if err := tx.Save(&existing).Error; err != nil {
					return err
				}
				endpoints[i].ID = existing.ID
				endpoints[i].FirstSeenAt = existing.FirstSeenAt
			case gorm.ErrRecordNotFound:
				endpoints[i].FirstSeenAt = time.Now()
				endpoints[i].LastSeenAt = time.Now()
				if err := tx.Create(&endpoints[i]).Error; err != nil {
					return err
				}
			default:
				return err
			}
		}
		return nil
	})
}

func (r *TargetEndpointRepo) ListByTarget(ctx context.Context, targetID uint) ([]domain.TargetEndpoint, error) {
	out := []domain.TargetEndpoint{}
	if err := r.db.WithContext(ctx).Where("target_id = ?", targetID).Order("host, port").Find(&out).Error; err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}
