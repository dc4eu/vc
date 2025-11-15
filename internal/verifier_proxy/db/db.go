package db

import (
	"context"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Service is the database service
type Service struct {
	cfg    *model.Cfg
	log    *logger.Log
	tracer *trace.Tracer
	client *mongo.Client
	db     *mongo.Database

	Sessions *SessionCollection
	Clients  *ClientCollection
}

// New creates a new database service
func New(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	s := &Service{
		cfg:    cfg,
		log:    log.New("db"),
		tracer: tracer,
	}

	var err error
	s.client, err = mongo.Connect(options.Client().ApplyURI(cfg.Common.Mongo.URI))
	if err != nil {
		s.log.Error(err, "Failed to connect to MongoDB")
		return nil, err
	}

	if err := s.client.Ping(ctx, nil); err != nil {
		s.log.Error(err, "Failed to ping MongoDB")
		return nil, err
	}

	s.db = s.client.Database("verifier_proxy")

	// Initialize collections
	s.Sessions = &SessionCollection{
		Service:    s,
		collection: s.db.Collection("sessions"),
	}

	s.Clients = &ClientCollection{
		Service:    s,
		collection: s.db.Collection("clients"),
	}

	s.log.Info("Connected to MongoDB")

	return s, nil
}

// Close closes the database connection
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Closing database connection")
	if s.client != nil {
		return s.client.Disconnect(ctx)
	}
	return nil
}
