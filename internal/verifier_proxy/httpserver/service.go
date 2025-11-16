package httpserver

import (
	"context"
	"net/http"
	"text/template"
	"time"
	"vc/internal/verifier_proxy/apiv1"
	"vc/internal/verifier_proxy/middleware"
	"vc/pkg/httphelpers"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

// Service is the service object for httpserver
type Service struct {
	cfg              *model.Cfg
	log              *logger.Log
	server           *http.Server
	apiv1            *apiv1.Client
	gin              *gin.Engine
	tracer           *trace.Tracer
	httpHelpers      *httphelpers.Client
	tokenLimiter     *middleware.RateLimiter
	authorizeLimiter *middleware.RateLimiter
	registerLimiter  *middleware.RateLimiter
}

// New creates a new httpserver service
func New(ctx context.Context, cfg *model.Cfg, apiv1 *apiv1.Client, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	// Initialize rate limiters with default configuration
	rateLimitConfig := middleware.DefaultRateLimitConfig()

	s := &Service{
		cfg:    cfg,
		log:    log.New("httpserver"),
		apiv1:  apiv1,
		gin:    gin.New(),
		tracer: tracer,
		server: &http.Server{
			ReadHeaderTimeout: 3 * time.Second,
		},
		tokenLimiter:     middleware.NewRateLimiter(rateLimitConfig.TokenRequestsPerMinute, rateLimitConfig.TokenBurst),
		authorizeLimiter: middleware.NewRateLimiter(rateLimitConfig.AuthorizeRequestsPerMinute, rateLimitConfig.AuthorizeBurst),
		registerLimiter:  middleware.NewRateLimiter(rateLimitConfig.RegisterRequestsPerMinute, rateLimitConfig.RegisterBurst),
	}

	var err error
	s.httpHelpers, err = httphelpers.New(ctx, s.tracer, s.cfg, s.log)
	if err != nil {
		return nil, err
	}

	rgRoot, err := s.httpHelpers.Server.Default(ctx, s.server, s.gin, s.cfg.VerifierProxy.APIServer.Addr)
	if err != nil {
		return nil, err
	}

	// Set up session store
	store := cookie.NewStore([]byte("secret-key-change-in-production"))
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   900, // 15 minutes
		HttpOnly: true,
		Secure:   s.cfg.VerifierProxy.APIServer.TLS.Enabled,
		SameSite: http.SameSiteLaxMode,
	})
	s.gin.Use(sessions.Sessions("verifier_proxy_session", store))

	// Templating functions
	s.gin.SetFuncMap(template.FuncMap{
		"json": func(v any) string {
			return ""
		},
	})

	// Load templates
	s.gin.LoadHTMLGlob("./internal/verifier_proxy/httpserver/static/*.html")

	// Health check
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "health", http.StatusOK, s.endpointHealth)

	// OIDC Discovery
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, ".well-known/openid-configuration", http.StatusOK, s.endpointDiscovery)

	// JWKS
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "jwks", http.StatusOK, s.endpointJWKS)

	// OIDC Endpoints with rate limiting
	rgRoot.GET("/authorize", s.authorizeLimiter.Middleware(), func(c *gin.Context) {
		k := "api_endpoint GET:/authorize"
		ctx, span := s.tracer.Start(ctx, k)
		defer span.End()
		res, err := s.endpointAuthorize(ctx, c)
		if err != nil {
			s.log.Debug("endpointAuthorize", "err", err)
			c.JSON(httphelpers.StatusCode(ctx, err), gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, res)
	})

	rgRoot.POST("/token", s.tokenLimiter.Middleware(), func(c *gin.Context) {
		k := "api_endpoint POST:/token"
		ctx, span := s.tracer.Start(ctx, k)
		defer span.End()
		res, err := s.endpointToken(ctx, c)
		if err != nil {
			s.log.Debug("endpointToken", "err", err)
			c.JSON(httphelpers.StatusCode(ctx, err), gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, res)
	})

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "userinfo", http.StatusOK, s.endpointUserInfo)

	// Dynamic Client Registration with rate limiting (RFC 7591, 7592)
	rgRoot.POST("/register", s.registerLimiter.Middleware(), func(c *gin.Context) {
		k := "api_endpoint POST:/register"
		ctx, span := s.tracer.Start(ctx, k)
		defer span.End()
		res, err := s.endpointRegisterClient(ctx, c)
		if err != nil {
			s.log.Debug("endpointRegisterClient", "err", err)
			c.JSON(httphelpers.StatusCode(ctx, err), gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, res)
	})
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "register/:client_id", http.StatusOK, s.endpointGetClientConfiguration)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPut, "register/:client_id", http.StatusOK, s.endpointUpdateClient)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodDelete, "register/:client_id", http.StatusNoContent, s.endpointDeleteClient)

	// OpenID4VP Endpoints
	rgVerification := rgRoot.Group("/verification")
	s.httpHelpers.Server.RegEndpoint(ctx, rgVerification, http.MethodGet, "request-object/:session_id", http.StatusOK, s.endpointRequestObject)
	s.httpHelpers.Server.RegEndpoint(ctx, rgVerification, http.MethodPost, "direct_post", http.StatusOK, s.endpointDirectPost)
	s.httpHelpers.Server.RegEndpoint(ctx, rgVerification, http.MethodGet, "callback", http.StatusOK, s.endpointCallback)

	// UI Endpoints
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "qr/:session_id", http.StatusOK, s.endpointQRCode)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "poll/:session_id", http.StatusOK, s.endpointPoll)

	// Run http server
	go func() {
		err := s.httpHelpers.Server.ListenAndServe(ctx, s.server, s.cfg.VerifierProxy.APIServer)
		if err != nil {
			s.log.Trace("listen_error", "error", err)
		}
	}()

	s.log.Info("Started")

	return s, nil
}

// Close closes the httpserver
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Stopping")
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}
