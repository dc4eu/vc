package simplequeue

import (
	"context"
	"vc/pkg/kvclient"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	retask "github.com/masv3971/goretask"
	"github.com/redis/go-redis/v9"
)

type queue interface {
	Enqueue(ctx context.Context, message any) (*retask.Job, error)
	Dequeue(ctx context.Context) error
	Wait(ctx context.Context) (*retask.Task, error)
}

// Service is the service object for queue
type Service struct {
	redisClient *redis.Client
	queueClient *retask.Client
	tp          *trace.Tracer
	log         *logger.Log
	cfg         *model.Cfg

	LadokSign           queue
	LadokValidate       queue
	LadokDelSigned      queue
	LadokPersistentSave queue
}

// New creates a new queue service
func New(ctx context.Context, kv *kvclient.Client, tracer *trace.Tracer, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	service := &Service{
		redisClient: kv.RedisClient,
		tp:          tracer,
		log:         log,
		cfg:         cfg,
	}
	var err error
	service.queueClient, err = retask.New(ctx, service.redisClient)
	if err != nil {
		return nil, err
	}

	service.LadokSign, err = NewLadokSign(ctx, service, cfg.Common.Queues.SimpleQueue.EduSealSign.Name, service.log.New("LadokSign"))
	if err != nil {
		return nil, err
	}

	service.LadokValidate, err = NewLadokValidate(ctx, service, cfg.Common.Queues.SimpleQueue.EduSealValidate.Name, service.log.New("LadokValidate"))
	if err != nil {
		return nil, err
	}

	service.LadokDelSigned, err = NewLadokDelSigned(ctx, service, cfg.Common.Queues.SimpleQueue.EduSealDelSigned.Name, service.log.New("LadokDelSigned"))
	if err != nil {
		return nil, err
	}

	service.LadokPersistentSave, err = NewLadokPersistentSave(ctx, service, cfg.Common.Queues.SimpleQueue.EduSealPersistentSave.Name, service.log.New("LadokPersistentSave"))
	if err != nil {
		return nil, err
	}

	service.log.Info("Started")

	return service, nil
}

// Close closes the service
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Stopped")
	return nil
}
