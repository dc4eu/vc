package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"vc/pkg/openid4vci"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

func (s *Service) endpointOAuthPar(ctx context.Context, c *gin.Context) (any, error) {
	if c.Request.Method != http.MethodPost {
		c.String(http.StatusMethodNotAllowed, "Method not allowed")
		return nil, nil
	}

	//s.log.Debug("par", "length", c.Request.ContentLength)

	//if c.Request.ContentLength > 400 {
	//	c.String(http.StatusBadRequest, "Content length too large")
	//	return nil, nil
	//}

	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAuthPar")
	defer span.End()

	s.log.Debug("PAR endpoint")

	s.log.Debug("PAR", "header", c.Request.Header)

	request := &openid4vci.PARRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "binding error")
		return nil, err
	}

	reply, err := s.apiv1.OAuthPar(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "par error")
		return nil, err
	}
	s.log.Debug("par", "reply", reply)

	c.SetAccepted("application/json")

	return reply, nil
}

func (s *Service) endpointOAuthAuthorize(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAuthorize")
	defer span.End()

	request := &openid4vci.AuthorizeRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.OAuthAuthorize(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	u := fmt.Sprintf("https://dev.wallet.sunet.se/cb?code=%s&state=%s", reply.Code, reply.State)

	c.SetAccepted("application/json")
	c.Redirect(http.StatusPermanentRedirect, u)

	return nil, nil
}

func (s *Service) endpointOAuthToken(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointToken")
	defer span.End()

	s.log.Debug("Token endpoint", "header", c.Request.Header)
	dpop := c.Request.Header.Get("DPoP")
	s.log.Debug("Token endpoint", "dpop", dpop)

	request := &openid4vci.TokenRequest{
		DPOP: dpop,
	}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	//c.ShouldBindHeader(request)
	reply, err := s.apiv1.OAuthToken(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.SetAccepted("application/json")

	return reply, nil
}

func (s *Service) endpointOAuth2Metadata(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointMetadata")
	defer span.End()

	reply, err := s.apiv1.OAuthMetadata(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.SetAccepted("application/json")
	return reply, nil
}
