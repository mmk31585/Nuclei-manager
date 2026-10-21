package domain

import "context"

type ScopeRepo interface {
	Create(ctx context.Context, e *ScopeEntry) error
	List(ctx context.Context) ([]ScopeEntry, error)
	Delete(ctx context.Context, id uint) error
}

type TargetRepo interface {
	Create(ctx context.Context, t *Target) error
	Get(ctx context.Context, id uint) (*Target, error)
	List(ctx context.Context) ([]Target, error)
	Update(ctx context.Context, t *Target) error
	Delete(ctx context.Context, id uint) error
}

type ProfileRepo interface {
	Create(ctx context.Context, p *Profile) error
	Get(ctx context.Context, id uint) (*Profile, error)
	List(ctx context.Context) ([]Profile, error)
	Update(ctx context.Context, p *Profile) error
	Delete(ctx context.Context, id uint) error
}

type TaskRepo interface {
	Create(ctx context.Context, t *Task) error
	Get(ctx context.Context, id uint) (*Task, error)
	List(ctx context.Context) ([]Task, error)
	Update(ctx context.Context, t *Task) error
	Delete(ctx context.Context, id uint) error
}

type TargetEndpointRepo interface {
	Upsert(ctx context.Context, endpoints []TargetEndpoint) error
	ListByTarget(ctx context.Context, targetID uint) ([]TargetEndpoint, error)
}
