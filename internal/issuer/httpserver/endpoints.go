package httpserver

import (
	"context"
	"vc/internal/issuer/apiv1"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointSignPDF(ctx context.Context, c *gin.Context) (interface{}, error) {
	request := &apiv1.PDFSignRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.PDFSign(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointValidatePDF(ctx context.Context, c *gin.Context) (interface{}, error) {
	request := &apiv1.PDFValidateRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.PDFValidate(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGetSignedPDF(ctx context.Context, c *gin.Context) (interface{}, error) {
	request := &apiv1.PDFGetSignedRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.PDFGetSigned(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointPDFRevoke(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.PDFRevokeRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.PDFRevoke(ctx, request)
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
