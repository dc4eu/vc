package httpserver

import (
	"context"
	"vc/internal/issuer/apiv1"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointSignPDF(ctx context.Context, c *gin.Context) (interface{}, error) {
	request := &apiv1.SignPDFRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.SignPDF(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGetSignedPDF(ctx context.Context, c *gin.Context) (interface{}, error) {
	request := &apiv1.GetSignedPDFRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.GetSignedPDF(ctx, request)
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
