package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

func (s *Service) endpointOAuthPar(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAuthPar")
	defer span.End()

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
		if errors.Is(err, oauth2.ErrInvalidClient) {
			c.AbortWithStatus(http.StatusMethodNotAllowed)
			return nil, nil
		}
		return nil, err
	}
	s.log.Debug("par", "reply", reply)

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

	tokenRequestHeader := &openid4vci.TokenRequestHeader{}
	if err := c.BindHeader(tokenRequestHeader); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "binding header error")
		return nil, err
	}

	request := &openid4vci.TokenRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	request.Header = tokenRequestHeader

	reply, err := s.apiv1.OAuthToken(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.SetAccepted("application/json")
	c.Redirect(http.StatusPermanentRedirect, request.RedirectURI)

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

func (s *Service) endpointOAuthAuthorizationConsent(ctx context.Context, c *gin.Context) (any, error) {
	c.HTML(http.StatusOK, "index.html", nil)
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAuthorizationConsent")
	defer span.End()

	request := &openid4vci.AuthorizationConsentRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return nil, nil
}

// login goes here
//func (s *Service) endpointOAuthAuthorizationConsentLogin(ctx context.Context, c *gin.Context) (any, error) {
//
//	request := &openid4vci.AuthorizationConsentLoginRequest{}
//	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
//		return nil, err
//	}
//
//	//reply, err := s.apiv1.OAuthAuthorizationConsentLogin(ctx, request)
//	//if err != nil {
//	//	return nil, err
//	//}
//
//	s.log.Debug("OAuthAuthorizationConsentLogin", "reply", reply)
//	return nil, nil
//}
