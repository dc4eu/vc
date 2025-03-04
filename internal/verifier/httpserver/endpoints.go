package httpserver

import (
	"context"
	"errors"
	"go.opentelemetry.io/otel/codes"
	"vc/internal/verifier/apiv1"
	"vc/pkg/openid4vp"

	"vc/internal/gen/status/apiv1_status"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointHealth(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Health(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointVerifyCredential(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointVerifyCredential")
	defer span.End()

	request := &apiv1.Credential{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.VerifyCredential(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointDecodeCredential(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDecodeCredential")
	defer span.End()

	request := &apiv1.Credential{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.DecodeCredential(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointQRCode(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointQRCode")
	defer span.End()

	request := &openid4vp.DocumentTypeEnvelope{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.GenerateQRCode(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointAuthorize(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAuthorize")
	defer span.End()

	sessionID := g.Query("session_id")
	nonce := g.Query("nonce")
	state := g.Query("state")

	if sessionID == "" || nonce == "" || state == "" {
		return nil, errors.New("sessionID or nonce or state is empty")
	}

	reply, err := s.apiv1.Authorize(ctx, sessionID, nonce, state)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGetRequestObject(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointRequestObject")
	defer span.End()

	sessionID := g.Param("session_id")
	if sessionID == "" {
		return nil, errors.New("session_id is empty")
	}

	reply, err := s.apiv1.GetRequestObject(ctx, sessionID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil

	return nil, nil
}
