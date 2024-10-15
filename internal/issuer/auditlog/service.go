package auditlog

import (
	"context"
	"sync"
	"vc/pkg/logger"
	"vc/pkg/model"
)

// AuditLog holds the request data for the SendWebHook method
type AuditLog struct {
	EventType string `json:"event"`
	Date      string `json:"date"`
	ID        string `json:"id"`
	Message   any    `json:"message"`
}

// Service holds auditlog service
type Service struct {
	cfg          *model.Cfg
	log          *logger.Log
	auditLogChan chan *AuditLog
	wg           sync.WaitGroup
}

// New creates a new auditlog service
func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	service := &Service{
		cfg:          cfg,
		log:          log.New("auditlog"),
		auditLogChan: make(chan *AuditLog),
	}

	service.wg.Add(1)
	go service.processAuditLog(ctx)

	service.log.Info("Started")

	return service, nil
}

// Close closes the auditlog service
func (s *Service) Close(ctx context.Context) error {
	ctx.Done()
	s.wg.Done()
	s.wg.Wait()

	s.log.Info("Stopped")

	return nil
}
