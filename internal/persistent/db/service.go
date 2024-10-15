package db

import (
	"context"
	"time"

	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"google.golang.org/protobuf/types/known/timestamppb"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Service is the database service
type Service struct {
	dbClient   *mongo.Client
	cfg        *model.Cfg
	log        *logger.Log
	tracer     *trace.Tracer
	probeStore *apiv1_status.StatusProbeStore

	VCDatastoreColl *VCDatastoreColl
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
		service: service,
		coll:    service.dbClient.Database("vc").Collection("datastore"),
	}
	if err := service.VCDatastoreColl.createIndex(ctx); err != nil {
		return nil, err
	}

	service.log.Info("Started")
	return service, nil
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

//credential := options.Credential{
//	AuthSource: "<authenticationDb>",
//	Username: "<username>",
//	Password: "<password>",
// }
// clientOpts := options.Client().ApplyURI("mongodb://<hostname>:<port>").
//	SetAuth(credential)
// client, err := mongo.Connect(context.TODO(), clientOpts)

// connect connects to the database
func (s *Service) connect(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "db:connect")
	defer span.End()

	//credentialOption := options.Credential{
	//	AuthSource: "<authenticationDb>",
	//	Username:   "<username>",
	//	Password:   "<password>",
	//}

	//clientOpts := options.Client().ApplyURI(s.cfg.Common.Mongo.URI).SetAuth(credentialOption)

	//	client, err := mongo.Connect(ctx, clientOpts)
	//	if err != nil {
	//		span.SetStatus(codes.Error, err.Error())
	//		return err
	//	}

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(s.cfg.Common.Mongo.URI))
	if err != nil {
		return err
	}
	s.dbClient = client

	return nil
}

// Close closes db service
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Stopped")
	return s.dbClient.Disconnect(ctx)
}
