package simplequeue

import (
	"context"
	"encoding/json"
	"vc/pkg/logger"

	retask "github.com/masv3971/goretask"
	"go.opentelemetry.io/otel/codes"
)

// LadokValidate is the ladok unsigned queue
type LadokValidate struct {
	service   *Service
	queueName string
	log       *logger.Log
	*retask.Queue
}

// NewLadokValidate creates a new ladok unsigned queue
func NewLadokValidate(ctx context.Context, service *Service, queueName string, log *logger.Log) (*LadokValidate, error) {
	ladokValidate := &LadokValidate{
		service: service,
		log:     log,
	}

	ladokValidate.Queue = ladokValidate.service.queueClient.NewQueue(ctx, queueName)

	ladokValidate.log.Info("Started")

	return ladokValidate, nil
}

// Enqueue publishes a document to the queue
func (s *LadokValidate) Enqueue(ctx context.Context, message any) (*retask.Job, error) {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:LadokValidate:Enqueue")
	defer span.End()

	data, err := json.Marshal(message)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return s.Queue.Enqueue(ctx, data)
}

// Wait waits for the next message
func (s *LadokValidate) Wait(ctx context.Context) (*retask.Task, error) {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:LadokValidate:Wait")
	defer span.End()

	return s.Queue.Wait(ctx)
}

// Dequeue dequeues a document from the queue
func (s *LadokValidate) Dequeue(ctx context.Context) error {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:LadokValidate:Dequeue")
	defer span.End()
	return nil
}
