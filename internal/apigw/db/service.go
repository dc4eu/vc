package db

import (
	"context"
	"errors"
	"time"

	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	// ErrNoDocuments is returned when no documents are found
	ErrNoDocuments = errors.New("no documents in result")
)

// DB is the interface for the database
type DB interface {
	//connect(ctx context.Context) error
	//Save(ctx context.Context, doc *model.Document) error
	//Get(ctx context.Context, transactionID string) (*model.Document, error)
}

// Service is the database service
type Service struct {
	dbClient   *mongo.Client
	cfg        *model.Cfg
	log        *logger.Log
	tracer     *trace.Tracer
	probeStore *apiv1_status.StatusProbeStore

	VCDatastoreColl       *VCDatastoreColl
	VCConsentColl         *VCConsentColl
	VCAuthzColl           *VCAuthzColl
	VCTokenColl           *VCTokenColl
	VCUsersColl           *VCUsersColl
	VCCodeChallengeColl   *VCCodeChallengeColl
	VCCredentialOfferColl *VCCredentialOfferColl
}

// New creates a new database service
func New(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	service := &Service{
		log:        log.New("db"),
		cfg:        cfg,
		tracer:     tracer,
		probeStore: &apiv1_status.StatusProbeStore{},
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	if err := service.connect(ctx); err != nil {
		return nil, err
	}

	service.VCDatastoreColl = &VCDatastoreColl{
		Service: service,
		Coll:    service.dbClient.Database("vc").Collection("datastore"),
		log:     log.New("VCDatastoreColl"),
	}
	if err := service.VCDatastoreColl.createIndex(ctx); err != nil {
		return nil, err
	}

	service.VCConsentColl = &VCConsentColl{
		Service: service,
		Coll:    service.dbClient.Database("vc").Collection("consent"),
		log:     log.New("VCConsentColl"),
	}
	if err := service.VCConsentColl.createIndex(ctx); err != nil {
		return nil, err
	}

	var err error

	service.VCAuthzColl, err = NewAuthzColl(ctx, "authz", service, log.New("VCAuthzColl"))
	if err != nil {
		return nil, err
	}

	service.VCTokenColl, err = NewTokenColl(ctx, "token", service, log.New("VCTokenColl"))
	if err != nil {
		return nil, err
	}

	service.VCUsersColl, err = NewUserColl(ctx, "users", service, log.New("VCUsersColl"))
	if err != nil {
		service.log.Error(err, "failed to create user collection")
		return nil, err
	}

	service.VCCodeChallengeColl, err = NewPkceColl(ctx, "code_challenge", service, log.New("VCCodeChallengeColl"))
	if err != nil {
		service.log.Error(err, "failed to create pkce collection")
		return nil, err
	}

	service.VCCredentialOfferColl, err = NewCredentialOfferColl(ctx, "credential_offer", service, log.New("VCCredentialOfferColl"))
	if err != nil {
		service.log.Error(err, "failed to create credential offer collection")
		return nil, err
	}

	service.log.Info("Started")

	return service, nil
}

// connect connects to the database
func (s *Service) connect(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "apigw:db:connect")
	defer span.End()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(s.cfg.Common.Mongo.URI))
	if err != nil {
		return err
	}
	s.dbClient = client

	return nil
}

// Status returns the status of the database
func (s *Service) Status(ctx context.Context) *apiv1_status.StatusProbe {
	ctx, span := s.tracer.Start(ctx, "db:status")
	defer span.End()

	if time.Now().Before(s.probeStore.NextCheck.AsTime()) {
		return s.probeStore.PreviousResult
	}
	probe := &apiv1_status.StatusProbe{
		Name:          "db",
		Healthy:       true,
		Message:       "OK",
		LastCheckedTS: timestamppb.Now(),
	}

	if err := s.dbClient.Ping(ctx, nil); err != nil {
		probe.Message = err.Error()
		probe.Healthy = false
	}

	s.probeStore.PreviousResult = probe
	s.probeStore.NextCheck = timestamppb.New(time.Now().Add(10 * time.Second))

	return probe
}

// Close closes the database connection
func (s *Service) Close(ctx context.Context) error {
	if err := s.dbClient.Disconnect(ctx); err != nil {
		return err
	}
	ctx.Done()
	return nil
}
