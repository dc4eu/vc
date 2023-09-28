package httpserver

import (
	"context"
	apiv1_registry "vc/internal/gen/registry/apiv1.registry"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointAdd(ctx context.Context, c *gin.Context) (interface{}, error) {
	request := &apiv1_registry.AddRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.Add(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointRevoke(ctx context.Context, c *gin.Context) (interface{}, error) {
	request := &apiv1_registry.RevokeRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.Revoke(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointValidate(ctx context.Context, c *gin.Context) (interface{}, error) {
	request := &apiv1_registry.ValidateRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.Validate(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointStatus(ctx context.Context, c *gin.Context) (interface{}, error) {
	reply, err := s.apiv1.Status(ctx)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
