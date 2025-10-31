package httpserver

import (
	"context"
	"vc/internal/verifier/apiv1"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointVerificationRequestObject(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointVerificationRequestObject called")

	request := &apiv1.VerificationRequestObjectRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.VerificationRequestObject(ctx, request)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointVerificationDirectPost(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointVerificationDirectPost called")

	reply, err := s.apiv1.VerificationDirectPost(ctx)
	if err != nil {
		return nil, err
	}

	return reply, nil
}
