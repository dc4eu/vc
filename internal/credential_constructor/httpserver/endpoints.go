package httpserver

import (
	"context"
	"vc/internal/credential_constructor/apiv1"

	"go.opentelemetry.io/otel/codes"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointSDJWT(ctx context.Context, c *gin.Context) (interface{}, error) {
	ctx, span := s.tp.Start(ctx, "httpserver:endpointSDJWT")
	defer span.End()

	request := &apiv1.SDJWTRequest{}
	if err := s.bindRequest(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.SDJWT(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}
