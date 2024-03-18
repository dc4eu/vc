package simplequeue

import (
	"context"
	"encoding/json"
	"vc/pkg/logger"

	retask "github.com/masv3971/goretask"
	"go.opentelemetry.io/otel/codes"
)

// VCPersistentSave holds the ladok delete signed queue
type VCPersistentDelete struct {
	service *Service
	log     *logger.Log
	*retask.Queue
}

// NewVCPersistentDelete creates a new queue for deletion of data
func NewVCPersistentDelete(ctx context.Context, service *Service, queueName string, log *logger.Log) (*VCPersistentDelete, error) {
	vcPersistentDelete := &VCPersistentDelete{
		service: service,
		log:     log,
	}

	vcPersistentDelete.Queue = vcPersistentDelete.service.queueClient.NewQueue(ctx, queueName)

	vcPersistentDelete.log.Info("Started")

	return vcPersistentDelete, nil
}

// Enqueue publishes a document to the queue
func (s *VCPersistentDelete) Enqueue(ctx context.Context, message any) (*retask.Job, error) {
	s.log.Info("Enqueue")
	ctx, span := s.service.tp.Start(ctx, "simplequeue:VCPersistentDelete:Enqueue")
	defer span.End()

	data, err := json.Marshal(message)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return s.Queue.Enqueue(ctx, data)
}

// Dequeue dequeues a document from the queue
func (s *VCPersistentDelete) Dequeue(ctx context.Context) error {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:VCPersistentDelete:Dequeue")
	defer span.End()
	return nil
}

// Wait waits for the next message
func (s *VCPersistentDelete) Wait(ctx context.Context) (*retask.Task, error) {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:VCPersistentDelete:Wait")
	defer span.End()

	task, err := s.Queue.Wait(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return task, nil
}
