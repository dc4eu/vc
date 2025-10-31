package httpserver

import (
	"context"
	"vc/internal/apigw/apiv1"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

func (s *Service) endpointStatusLists(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointStatusLists")
	defer span.End()

	request := &apiv1.StatusListsRequest{}
	if err := s.httpHelpers.Binding.RequestV2(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	s.log.Debug("endpointStatusLists", "request", request)
	reply, err := s.apiv1.StatusLists(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}
