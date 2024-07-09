package simplequeue

import (
	"context"
	"encoding/json"
	"vc/pkg/logger"
	"vc/pkg/model"

	retask "github.com/masv3971/goretask"
	"go.opentelemetry.io/otel/codes"
)

// VCPersistentReplace holds the ladok delete signed queue
type VCPersistentReplace struct {
	service *Service
	log     *logger.Log
	*retask.Queue
}

// NewVCPersistentReplace replaces a document in the queue
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
	s.log.Info("Enqueue")
	ctx, span := s.service.tp.Start(ctx, "simplequeue:VCPersistentReplace:Enqueue")
	defer span.End()

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

// Worker is the worker
func (s *VCPersistentReplace) Worker(ctx context.Context) error {
	ctx, span := s.service.tp.Start(ctx, "simplequeue:VCPersistentReplace:Worker")
	defer span.End()

	var (
		taskChan = make(chan *retask.Task)
		errChan  = make(chan error)
	)

	go func() {
		for {
			task, err := s.Wait(ctx)
			if err != nil {
				errChan <- err
			}
			taskChan <- task
		}
	}()

	for {
		select {
		case err := <-errChan:
			s.log.Error(err, "Worker failed")
			return err
		case task := <-taskChan:
			s.log.Info("Got task", "task", task.Data)
			document := &model.UploadDocument{}
			if err := json.Unmarshal([]byte(task.Data), document); err != nil {
				span.SetStatus(codes.Error, err.Error())
				s.log.Error(err, "Unmarshal failed")
			}
			if err := s.service.db.VCDatastoreColl.Replace(ctx, document); err != nil {
				span.SetStatus(codes.Error, err.Error())
				s.log.Error(err, "replace failed")
			}

		case <-ctx.Done():
			s.log.Info("Stopped worker")
			return nil
		}
	}
}
