package statusissuer

import (
	"context"
	"vc/internal/apigw/db"
	"vc/pkg/logger"
)

type Service struct {
	db  *db.Service
	log *logger.Log
}

func New(ctx context.Context, db *db.Service, log *logger.Log) (*Service, error) {
	s := &Service{
		db:  db,
		log: log,
	}

	for _, status := range []uint8{1, 2, 3} {
		section, index, err := s.AddStatus(ctx, status)
		if err != nil {
			return nil, err
		}
		s.log.Info("Added status to status list", "status", status, "index", index, "section", section)
	}

	return s, nil
}

func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Closing status issuer service")
	return nil
}
