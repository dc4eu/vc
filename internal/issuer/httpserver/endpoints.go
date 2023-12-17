package httpserver

import (
	"context"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/internal/issuer/apiv1"

	"go.opentelemetry.io/otel/codes"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointSignPDF(ctx context.Context, c *gin.Context) (interface{}, error) {
	ctx, span := s.tp.Start(ctx, "httpserver:endpointSignPDF")
	defer span.End()

	request := &apiv1.PDFSignRequest{}
	if err := s.bindV2(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.PDFSign(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointValidatePDF(ctx context.Context, c *gin.Context) (interface{}, error) {
	ctx, span := s.tp.Start(ctx, "httpserver:endpointValidatePDF")
	defer span.End()

	request := &apiv1.PDFValidateRequest{}
	if err := s.bindRequest(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.PDFValidate(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGetSignedPDF(ctx context.Context, c *gin.Context) (interface{}, error) {
	ctx, span := s.tp.Start(ctx, "httpserver:endpointGetSignedPDF")
	defer span.End()

	request := &apiv1.PDFGetSignedRequest{}
	if err := s.bindRequest(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.PDFGetSigned(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointPDFRevoke(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tp.Start(ctx, "httpserver:endpointPDFRevoke")
	defer span.End()

	request := &apiv1.PDFRevokeRequest{}
	if err := s.bindRequest(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.PDFRevoke(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGenericGet(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tp.Start(ctx, "httpserver:endpointGet")
	defer span.End()

	request := &apiv1.GetRequest{}
	if err := s.bindRequest(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.Get(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGenericRevoke(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tp.Start(ctx, "httpserver:endpointRevoke")
	defer span.End()

	request := &apiv1.RevokeRequest{}
	if err := s.bindRequest(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.Revoke(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointSatosaCredential(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tp.Start(ctx, "httpserver:endpointSatosaCredential")
	defer span.End()

	request := &apiv1.SatosaCredentialRequest{}
	if err := s.bindRequest(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.SatosaCredential(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}


func (s *Service) endpointCredential(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tp.Start(ctx, "httpserver:endpointCredential")
	defer span.End()

	request := &apiv1.CredentialRequest{}
	if err := s.bindRequest(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.Credential(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointStatus(ctx context.Context, c *gin.Context) (interface{}, error) {
	ctx, span := s.tp.Start(ctx, "httpserver:endpointStatus")
	defer span.End()

	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Status(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}
