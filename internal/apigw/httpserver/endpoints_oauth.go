package httpserver

import (
	"context"
	"errors"
	"net/http"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"

	"github.com/gin-contrib/sessions"
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
	session := sessions.Default(c)

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

	session.Set("scope", reply.Scope)
	session.Set("request_uri", request.RequestURI)
	if err := session.Save(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "session save error")
		return nil, err
	}

	s.log.Debug("Authorize endpoint", "requestURI", request.RequestURI, "reply", reply)

	c.SetAccepted("application/json")
	c.Redirect(http.StatusFound, reply.RedirectURL)

	return nil, nil
}

// after authorize and before token endpoint is authorization/consent be placed

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

	s.log.Debug("Token endpoint", "redirectURI", request.RedirectURI, "reply", reply)

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
	s.log.Debug("endpointOAuthAuthorizationConsent", "c.Request.URL", c.Request.URL.String(), "headers", c.Request.Header)
	_, span := s.tracer.Start(ctx, "httpserver:endpointAuthorizationConsent")
	defer span.End()

	session := sessions.Default(c)
	scope := session.Get("scope")
	if scope == nil {
		err := errors.New("scope not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "scope not found in session")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
	}

	c.SetCookie("scope", scope.(string), 900, "/authorization/consent", "", false, false)

	c.HTML(http.StatusOK, "index.html", nil)
	return nil, nil
}
