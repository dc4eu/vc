package httpserver

import (
	"context"
	"errors"
	"fmt"
	"github.com/gin-contrib/sessions"
	"go.opentelemetry.io/otel/codes"
	"vc/internal/gen/status/apiv1_status"
	"vc/internal/verifier/apiv1"
	"vc/pkg/openid4vp"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointQRCode(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointQRCode")
	defer span.End()

	request := &openid4vp.DocumentTypeEnvelope{}
	if err := s.httpHelpers.Binding.Request(ctx, g, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.GenerateQRCode(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if reply.SessionID == "" {
		span.SetStatus(codes.Error, "SessionID is empty")
		return nil, errors.New("SessionID is empty")
	}

	webSession := sessions.Default(g)
	webSession.Clear()
	// bind this web session to the current backend vp session stored else-where (to be used later for result checks)
	webSession.Set("vp_session_id", reply.SessionID)
	err = webSession.Save()
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointGetAuthorizationRequest(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointGetAuthorizationRequest")
	defer span.End()

	sessionID := g.Query("id")
	if sessionID == "" {
		return nil, errors.New("id is empty")
	}

	reply, err := s.apiv1.GetAuthorizationRequest(ctx, sessionID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointCallback(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointCallback")
	defer span.End()

	sessionID := g.Param("session_id")
	if sessionID == "" {
		return nil, errors.New("session_id is empty")
	}
	callbackID := g.Param("callback_id")
	if callbackID == "" {
		return nil, errors.New("callback_id is empty")
	}

	request := &openid4vp.AuthorizationResponse{}
	if err := s.httpHelpers.Binding.Request(ctx, g, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.Callback(ctx, sessionID, callbackID, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGetVerificationResult(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointGetVerificationResult")
	defer span.End()

	webSession := sessions.Default(g)
	vpSessionID, err := s.extractVPSessionIDfrom(webSession)
	if err != nil {
		return nil, errors.New("no web session found or has expired")
	}

	reply, err := s.apiv1.GetVerificationResult(ctx, vpSessionID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointQuitVPFlow(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointQuitVPFlow")
	defer span.End()

	webSession := sessions.Default(g)
	vpSessionID, err := s.extractVPSessionIDfrom(webSession)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	webSession.Clear()
	webSession.Options(sessions.Options{MaxAge: -1})
	err = webSession.Save()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	fmt.Println("web session removed for vpSessionID:", vpSessionID)
	//TODO: ta även bort vpSession om sådan finns lagrad (om man vill det före den timat ut av sig själv?) - kan ju dock pågå interaktion från en wallet samtidigt???

	return nil, nil
}

func (s *Service) extractVPSessionIDfrom(webSession sessions.Session) (string, error) {
	rawVPSessionID := webSession.Get("vp_session_id")
	if rawVPSessionID == nil {
		return "", errors.New("vp_session_id not found")
	}
	vpSessionID, ok := rawVPSessionID.(string)
	if !ok || vpSessionID == "" {
		return "", errors.New("vp_session_id not found or empty")
	}
	return vpSessionID, nil
}

func (s *Service) endpointHealth(ctx context.Context, g *gin.Context) (any, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Health(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// endpointVerifyCredential deprecated - to be removed (after removal in vc ui)
func (s *Service) endpointVerifyCredential(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointVerifyCredential")
	defer span.End()

	request := &apiv1.Credential{}
	if err := s.httpHelpers.Binding.Request(ctx, g, request); err != nil {
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

// endpointDecodeCredential deprecated - to be removed (after removal in vc ui)
func (s *Service) endpointDecodeCredential(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDecodeCredential")
	defer span.End()

	request := &apiv1.Credential{}
	if err := s.httpHelpers.Binding.Request(ctx, g, request); err != nil {
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
