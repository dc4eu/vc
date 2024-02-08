package simplequeue

import (
	"context"
	"encoding/json"
	"vc/pkg/logger"

	retask "github.com/masv3971/goretask"
	"go.opentelemetry.io/otel/codes"
)

// LadokDelSigned holds the ladok delete signed queue
type LadokDelSigned struct {
	service *Service
	log     *logger.Log
	*retask.Queue
}

// NewLadokDelSigned creates a new ladok delete signed queue
func NewLadokDelSigned(ctx context.Context, service *Service, queueName string, log *logger.Log) (*LadokDelSigned, error) {
	ladokDelSigned := &LadokDelSigned{
		service: service,
		log:     log,
	}

	ladokDelSigned.Queue = ladokDelSigned.service.queueClient.NewQueue(ctx, queueName)

	ladokDelSigned.log.Info("Started")

	return ladokDelSigned, nil
}

// Enqueue publishes a document to the queue
func (s *LadokDelSigned) Enqueue(ctx context.Context, message any) (*retask.Job, error) {
	s.log.Info("Enqueue delete signed pdf")
	ctx, span := s.service.tp.Start(ctx, "simplequeue:LadokDelSigned:Enqueue")
	defer span.End()

	data, err := json.Marshal(message)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return s.Queue.Enqueue(ctx, data)
}

// Dequeue dequeues a document from the queue
func (s *LadokDelSigned) Dequeue(ctx context.Context) error {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:LadokDelSigned:Dequeue")
	defer span.End()
	return nil
}

// Wait waits for the next message
func (s *LadokDelSigned) Wait(ctx context.Context) (*retask.Task, error) {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:LadokDelSigned:Wait")
	defer span.End()

	task, err := s.Queue.Wait(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return task, nil
}
