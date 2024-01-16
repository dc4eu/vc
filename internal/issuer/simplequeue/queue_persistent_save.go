package simplequeue

import (
	"context"
	"encoding/json"
	"vc/pkg/logger"

	retask "github.com/masv3971/goretask"
	"go.opentelemetry.io/otel/codes"
)

// LadokPersistentSave holds the ladok delete signed queue
type LadokPersistentSave struct {
	service *Service
	log     *logger.Log
	*retask.Queue
}

// NewLadokPersistentSave creates a new ladok delete signed queue
func NewLadokPersistentSave(ctx context.Context, service *Service, queueName string, log *logger.Log) (*LadokDelSigned, error) {
	ladokPersistentSave := &LadokDelSigned{
		service: service,
		log:     log,
	}

	ladokPersistentSave.Queue = ladokPersistentSave.service.queueClient.NewQueue(ctx, queueName)

	ladokPersistentSave.log.Info("Started")

	return ladokPersistentSave, nil
}

// Enqueue publishes a document to the queue
func (s *LadokPersistentSave) Enqueue(ctx context.Context, message any) (*retask.Job, error) {
	s.log.Info("Enqueue delete signed pdf")
	ctx, span := s.service.tp.Start(ctx, "simplequeue:LadokPersistentSave:Enqueue")
	defer span.End()

	data, err := json.Marshal(message)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return s.Queue.Enqueue(ctx, data)
}

// Dequeue dequeues a document from the queue
func (s *LadokPersistentSave) Dequeue(ctx context.Context) error {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:LadokPersistentSave:Dequeue")
	defer span.End()
	return nil
}

// Wait waits for the next message
func (s *LadokPersistentSave) Wait(ctx context.Context) (*retask.Task, error) {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:LadokPersistentSave:Wait")
	defer span.End()

	task, err := s.Queue.Wait(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return task, nil
}
