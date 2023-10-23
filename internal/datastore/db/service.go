package db

import (
	"context"
	"errors"
	"time"

	"vc/pkg/logger"
	"vc/pkg/model"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	// ErrNoDocuments is returned when no documents are found
	ErrNoDocuments = errors.New("No documents in result")
)

// DB is the interface for the database
type DB interface {
	//connect(ctx context.Context) error
	//Save(ctx context.Context, doc *model.Document) error
	//Get(ctx context.Context, transactionID string) (*model.Document, error)
}

// Service is the database service
type Service struct {
	DBClient *mongo.Client
	cfg      *model.Cfg
	log      *logger.Log

	Coll *Coll
}

// New creates a new database service
func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	service := &Service{
		log: log,
		cfg: cfg,
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	if err := service.connect(ctx); err != nil {
		return nil, err
	}

	service.Coll = &Coll{
		Service: service,
		Coll:    service.DBClient.Database("datastore").Collection("generic"),
	}

	service.log.Info("Started")

	return service, nil
}

// connect connects to the database
func (s *Service) connect(ctx context.Context) error {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(s.cfg.Common.Mongo.URI))
	if err != nil {
		return err
	}
	s.DBClient = client

	return nil
}

// Close closes the database connection
func (s *Service) Close(ctx context.Context) error {
	if err := s.DBClient.Disconnect(ctx); err != nil {
		return err
	}
	ctx.Done()
	return nil
}
