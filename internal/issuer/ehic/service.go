package ehic

import (
	"context"
	"vc/pkg/logger"
	"vc/pkg/model"
)

// Service holds EHIC service object
type Service struct {
	cfg *model.Cfg
	log *logger.Log
}

// New creates a new instance of the service, or error
func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	s := &Service{
		log: log,
		cfg: cfg,
	}

	s.log.Info("Started")
	return s, nil
}

// Close closes the service
func (s *Service) Close(ctx context.Context) error {
	ctx.Done()
	return nil
}
