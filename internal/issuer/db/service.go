package db

import (
	"context"

	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// Service is the database service
type Service struct {
	dbClient *mongo.Client
	cfg      *model.Cfg
	log      *logger.Log
	tp       *trace.Tracer

	DocumentsColl PDFColl
}

// New creates a new database service
func New(ctx context.Context, cfg *model.Cfg, tp *trace.Tracer, log *logger.Log) (*Service, error) {
	service := &Service{
		log: log,
		cfg: cfg,
		tp:  tp,
	}

	if err := service.connect(ctx); err != nil {
		return nil, err
	}

	service.DocumentsColl = PDFColl{
		service: service,
		coll:    service.dbClient.Database("issuer").Collection("documents"),
	}
	service.DocumentsColl.createIndex(ctx)

	service.log.Info("Started")
	return service, nil
}

// connect connects to the database
func (s *Service) connect(ctx context.Context) error {
	ctx, span := s.tp.Start(ctx, "db:connect")
	defer span.End()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(s.cfg.Common.Mongo.URI))
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	s.dbClient = client

	return nil
}

// Close closes db service
func (s *Service) Close(ctx context.Context) error {
	return s.dbClient.Disconnect(ctx)
}
