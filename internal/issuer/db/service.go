package db

import (
	"context"
	"time"

	"vc/pkg/logger"
	"vc/pkg/model"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// DB is the interface for the database
type DB interface {
	connect(ctx context.Context) error
	SaveTransaction(ctx context.Context, doc *model.Transaction) error
	GetTransation(ctx context.Context, transationID string) (*model.Transaction, error)
}

// Service is the database service
type Service struct {
	dbClient *mongo.Client
	cfg      *model.Cfg
	log      *logger.Logger

	dbIssuer   *mongo.Database
	dbVerifier *mongo.Database

	CollIssuerTransactions *mongo.Collection
}

// New creates a new database service
func New(ctx context.Context, cfg *model.Cfg, log *logger.Logger) (*Service, error) {
	service := &Service{
		log: log,
		cfg: cfg,
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	if err := service.connect(ctx); err != nil {
		return nil, err
	}

	return service, nil
}

// connect connects to the database
func (s *Service) connect(ctx context.Context) error {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(s.cfg.Issuer.Mongo.URI))
	if err != nil {
		return err
	}
	s.dbClient = client
	s.dbIssuer = client.Database("issuer")
	s.dbVerifier = client.Database("verifier")

	s.CollIssuerTransactions = s.dbIssuer.Collection("transactions")

	return nil
}

// Close closes db service
func (s *Service) Close(ctx context.Context) error {
	return s.dbClient.Disconnect(ctx)
}
