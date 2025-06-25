package httpserver

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"vc/internal/apigw/apiv1"
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
	session.Set("auth_method", s.cfg.GetCredentialConstructorAuthMethod(reply.Scope))
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
	authMethod := session.Get("auth_method")
	if authMethod == nil {
		err := errors.New("auth_method not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "auth_method not found in session")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
	}

	c.SetCookie("auth_method", authMethod.(string), 900, "/authorization/consent", "", false, false)

	if authMethod == "pid_auth" {
		request := &apiv1.OauthAuthorizationConsentRequest{
			AuthMethod: authMethod.(string),
		}

		reply, err := s.apiv1.OAuthAuthorizationConsent(ctx, request)
		if err != nil {
			return nil, err
		}

		c.SetCookie("pid_auth_redirect_url", reply.RedirectURL, 900, "/authorization/consent", "", false, false)
	}

	c.HTML(http.StatusOK, "index.html", nil)
	return nil, nil
}

type SVGTemplateReply struct {
	Template  string               `json:"template"`
	SVGClaims map[string][]*string `json:"svg_claims"`
}

func (s *Service) endpointOAuthAuthorizationConsentSvgTemplate(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointOAuthAuthorizationConsentSvgTemplate", "c.Request.URL", c.Request.URL.String(), "headers", c.Request.Header)
	_, span := s.tracer.Start(ctx, "httpserver:endpointOAuthAuthorizationConsentSvgTemplate")
	defer span.End()

	session := sessions.Default(c)

	scope, ok := session.Get("scope").(string)
	if !ok {
		err := errors.New("scope not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "scope not found in session")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
	}

	credentialConstructor, ok := s.cfg.CredentialConstructor[scope]
	if !ok {
		err := errors.New("scope is not valid credential")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "scope is not valid credential")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
	}

	if err := credentialConstructor.LoadFile(ctx); err != nil {
		return nil, err
	}

	vctm := credentialConstructor.VCTM

	svgClaims := make(map[string][]*string)

	for _, claim := range vctm.Claims {
		if claim.SVGID != "" {
			svgClaims[claim.SVGID] = claim.Path
		}
	}

	svgTemplateURI := vctm.Display[0].Rendering.SVGTemplates[0].URI

	response, err := http.Get(svgTemplateURI)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "fetching svg template failed")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		err := errors.New("non ok response code from svg template origin")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "non ok response code from svg template origin")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
	}

	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "reading svg template failed")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
	}

	template := base64.StdEncoding.EncodeToString([]byte(responseData))

	reply := SVGTemplateReply{
		Template:  template,
		SVGClaims: svgClaims,
	}

	c.SetAccepted("application/json")
	return reply, nil
}
