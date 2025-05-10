package httpserver

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
	"vc/pkg/vcclient"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointHealth(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Status(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGetUserCredentialOffers(ctx context.Context, g *gin.Context) (any, error) {
	request := &vcclient.LoginPIDUserRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, g, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.GetUserCredentialOffers(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// Deprecated: TODO: remove this endpoint when endpointGetUserCredentialOffers is working
func (s *Service) endpointSearchDocuments(ctx context.Context, c *gin.Context) (any, error) {
	request := &model.SearchDocumentsRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.SearchDocuments(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
