package httpserver

import (
	"context"
	"net/http"
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

	request := &apiv1.VerificationDirectPostRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}
	s.log.Debug("endpointVerificationDirectPost", "here", "after binding")

	reply, err := s.apiv1.VerificationDirectPost(ctx, request)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointVerificationCallback(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointVerificationCallback called")

	request := &apiv1.VerificationCallbackRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.VerificationCallback(ctx, request)
	if err != nil {
		return nil, err
	}

	c.HTML(http.StatusOK, "callback.html", reply)

	return nil, nil
}
