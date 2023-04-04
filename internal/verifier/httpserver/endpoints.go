package httpserver

import (
	"context"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointStatus(ctx context.Context, c *gin.Context) (interface{}, error) {
	reply, err := s.apiv1.Status(ctx)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointMonitoringCertClient(ctx context.Context, c *gin.Context) (interface{}, error) {
	reply, err := s.apiv1.MonitoringCertClient(ctx)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
