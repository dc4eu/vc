package simplequeue

import (
	"context"
	"encoding/json"
	"vc/pkg/logger"

	retask "github.com/masv3971/goretask"
	"go.opentelemetry.io/otel/codes"
)

// LadokSign is the ladok unsigned queue
type LadokSign struct {
	service *Service
	log     *logger.Log
	*retask.Queue
}

// NewLadokSign creates a new ladok unsigned queue
func NewLadokSign(ctx context.Context, service *Service, queueName string, log *logger.Log) (*LadokSign, error) {
	ladokSign := &LadokSign{
		service: service,
		log:     log,
	}

	ladokSign.Queue = ladokSign.service.queueClient.NewQueue(ctx, queueName)

	ladokSign.log.Info("Started")

	return ladokSign, nil
}

// Enqueue publishes a document to the queue
func (s *LadokSign) Enqueue(ctx context.Context, message any) (*retask.Job, error) {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:LadokSign:Enqueue")
	defer span.End()

	data, err := json.Marshal(message)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return s.Queue.Enqueue(ctx, data)
}

// Dequeue dequeues a document from the queue
func (s *LadokSign) Dequeue(ctx context.Context) error {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:LadokSign:Dequeue")
	defer span.End()
	return nil
}

// Wait waits for the next message
func (s *LadokSign) Wait(ctx context.Context) (*retask.Task, error) {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:LadokSign:Wait")
	defer span.End()
	return nil, nil
}
