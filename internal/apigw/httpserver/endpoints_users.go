package httpserver

import (
	"context"
	"errors"
	"net/http"
	"vc/pkg/model"
	"vc/pkg/vcclient"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

func (s *Service) endpointAddPIDUser(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAddPIDUser")
	defer span.End()

	request := &vcclient.AddPIDRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	err := s.apiv1.AddPIDUser(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return nil, nil
}

func (s *Service) endpointLoginPIDUser(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointLoginPIDUser")
	defer span.End()
	session := sessions.Default(c)

	requestURI, ok := session.Get("request_uri").(string)
	if !ok {
		err := errors.New("request_uri not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "endpointLoginPIDUser: request_uri not found in session")
		return nil, err
	}

	s.log.Debug("endpointLoginPIDUser", "requestURI", requestURI)

	s.log.Debug("endpointLoginPIDUser", "method", c.Request.Method, "path", c.Request.URL.Path, "headers", c.Request.Header)
	request := &vcclient.LoginPIDUserRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	request.RequestURI = requestURI

	reply, err := s.apiv1.LoginPIDUser(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	session.Set("username", request.Username)
	if err := session.Save(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "session save error")
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointUserLookup(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointUserLookup")
	defer span.End()

	request := &vcclient.UserLookupRequest{}

	session := sessions.Default(c)
	authMethod, ok := session.Get("auth_method").(string)
	if !ok {
		err := errors.New("auth_method not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "endpointUserLookup: auth_method not found in session")
		return nil, err
	}

	request.AuthMethod = authMethod

	switch authMethod {
	case model.AuthMethodBasic:
		username, ok := session.Get("username").(string)
		if !ok {
			err := errors.New("username not found in session")
			span.SetStatus(codes.Error, err.Error())
			s.log.Error(err, "endpointUserLookup: username not found in session")
			return nil, err
		}

		request.Username = username
	case model.AuthMethodPID:

	default:
		err := errors.New("unsupported auth method for user lookup")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "endpointUserLookup: unsupported auth method", "auth_method", authMethod)
		return nil, err
	}

	reply, err := s.apiv1.UserLookup(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointUserCancel(ctx context.Context, c *gin.Context) (any, error) {
	_, span := s.tracer.Start(ctx, "httpserver:endpointUserCancel")
	defer span.End()

	session := sessions.Default(c)

	clientId, ok := session.Get("client_id").(string)
	if !ok {
		err := errors.New("client_id not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "endpointUserCancel: client_id not found in session")
		return nil, err
	}

	session.Clear()

	if err := session.Save(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "session save error")
		return nil, err
	}

	// Delete all cookies, not just session.
	c.SetCookie("auth_method", "", -1, "/authorization/consent", "", false, false)
	c.SetCookie("pid_auth_redirect_url", "", -1, "/authorization/consent", "", false, false)

	client, ok := s.cfg.APIGW.OauthServer.Clients[clientId]
	if !ok {
		err := errors.New("invalid client_id")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "endpointUserCancel: invalid client_id")
		return nil, err
	}

	c.Redirect(http.StatusSeeOther, client.RedirectURI)

	return nil, nil
}
