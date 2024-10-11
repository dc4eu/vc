package db

import (
	"context"
	"vc/pkg/logger"
	"vc/pkg/model"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Service is the database service
type Service struct {
	db  *gorm.DB
	log *logger.Log
	cfg *model.Cfg
}

// New creates a new database service
func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	s := &Service{
		log: log.New("db"),
		cfg: cfg,
	}
	if err := s.startDB(); err != nil {
		return nil, err
	}

	s.log.Info("Started")

	return s, nil
}

func (s *Service) startDB() error {
	var err error
	s.db, err = gorm.Open(sqlite.Open("/tmp/test.db"), &gorm.Config{})
	if err != nil {
		return err
	}
	if err := s.db.AutoMigrate(&model.Leaf{}); err != nil {
		return err
	}

	return nil
}

// Close closes the database connection
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Stopped")
	ctx.Done()
	return nil
}
