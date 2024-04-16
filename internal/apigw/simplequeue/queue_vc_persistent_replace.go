package simplequeue

import (
	"context"
	"encoding/json"
	"vc/pkg/logger"

	retask "github.com/masv3971/goretask"
	"go.opentelemetry.io/otel/codes"
)

// VCPersistentReplace holds the ladok delete signed queue
type VCPersistentReplace struct {
	service *Service
	log     *logger.Log
	*retask.Queue
}

// NewVCPersistentReplace updates an existing vc document
func NewVCPersistentReplace(ctx context.Context, service *Service, queueName string, log *logger.Log) (*VCPersistentReplace, error) {
	vcPersistentReplace := &VCPersistentReplace{
		service: service,
		log:     log,
	}

	vcPersistentReplace.Queue = vcPersistentReplace.service.queueClient.NewQueue(ctx, queueName)

	vcPersistentReplace.log.Info("Started")

	return vcPersistentReplace, nil
}

// Enqueue publishes a document to the queue
func (s *VCPersistentReplace) Enqueue(ctx context.Context, message any) (*retask.Job, error) {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:VCPersistentReplace:Enqueue")
	defer span.End()

	s.log.Debug("Enqueue", "message", message)

	data, err := json.Marshal(message)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return s.Queue.Enqueue(ctx, data)
}

// Dequeue dequeues a document from the queue
func (s *VCPersistentReplace) Dequeue(ctx context.Context) error {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:VCPersistentReplace:Dequeue")
	defer span.End()
	return nil
}

// Wait waits for the next message
func (s *VCPersistentReplace) Wait(ctx context.Context) (*retask.Task, error) {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:VCPersistentReplace:Wait")
	defer span.End()

	task, err := s.Queue.Wait(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return task, nil
}
