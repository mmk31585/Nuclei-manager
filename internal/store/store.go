package store

import (
	"context"
	"fmt"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

type Store struct {
	DB       *gorm.DB
	Scope    *ScopeRepo
	Targets  *TargetRepo
	Profiles *ProfileRepo
	Tasks    *TaskRepo
	Runs     *RunRepo
}

func Open(dsn string) (*Store, error) {
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Error),
	})
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get sql db: %w", err)
	}
	sqlDB.SetMaxOpenConns(20)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return &Store{
		DB:       db,
		Scope:    NewScopeRepo(db),
		Targets:  NewTargetRepo(db),
		Profiles: NewProfileRepo(db),
		Tasks:    NewTaskRepo(db),
		Runs:     NewRunRepo(db),
	}, nil
}

func (s *Store) Migrate() error {
	return s.DB.AutoMigrate(
		&domain.ScopeEntry{}, &domain.Target{}, &domain.Profile{}, &domain.Task{},
		&domain.Run{}, &domain.Finding{}, &domain.RunFinding{},
		&domain.CustomTemplate{}, &domain.Suppression{},
	)
}

func (s *Store) Ping(ctx context.Context) error {
	sqlDB, err := s.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

func (s *Store) Close() error {
	sqlDB, err := s.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
