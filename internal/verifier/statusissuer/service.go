package statusissuer

import (
	"context"
	"vc/internal/verifier/db"
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
		got, err := s.db.StatusListColl.Add(ctx, status)
		if err != nil {
			return nil, err
		}
		s.log.Info("Added status to status list", "status", status, "index", got)

		section, err := s.db.StatusListMetadataDoc.GetCurrentSection(ctx)
		if err != nil {
			return nil, err
		}

		gotV2, err := s.db.StatusListV2Coll.Add(ctx, int(section), status)
		if err != nil {
			return nil, err
		}
		s.log.Info("Added status to status list v2", "status", status, "index", gotV2)
	}

	if err := s.db.StatusListColl.UpdateRandomDecoy(ctx); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Closing status issuer service")
	return nil
}
