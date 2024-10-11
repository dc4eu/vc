package httpserver

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/internal/issuer/apiv1"

	"go.opentelemetry.io/otel/codes"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointCreateCredential(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointCredential")
	defer span.End()

	request := &apiv1.CreateCredentialRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.MakeSDJWT(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointHealth(ctx context.Context, c *gin.Context) (interface{}, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointHealth")
	defer span.End()

	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Health(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}
