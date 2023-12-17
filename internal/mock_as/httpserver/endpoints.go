package httpserver

import (
	"context"
	"vc/internal/mock_as/apiv1"

	"go.opentelemetry.io/otel/codes"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointMockNext(ctx context.Context, c *gin.Context) (interface{}, error) {
	ctx, span := s.tp.Start(ctx, "httpserver:endpointMockNext")
	defer span.End()

	request := &apiv1.MockNextRequest{}
	if err := s.bindRequest(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.MockNext(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}
