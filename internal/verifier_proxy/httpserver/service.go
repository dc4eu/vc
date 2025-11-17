package httpserver

import (
	"context"
	"net/http"
	"text/template"
	"time"
	"vc/internal/verifier_proxy/apiv1"
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
	cfg         *model.Cfg
	log         *logger.Log
	server      *http.Server
	apiv1       *apiv1.Client
	gin         *gin.Engine
	tracer      *trace.Tracer
	httpHelpers *httphelpers.Client
}

// New creates a new httpserver service
func New(ctx context.Context, cfg *model.Cfg, apiv1 *apiv1.Client, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	s := &Service{
		cfg:    cfg,
		log:    log.New("httpserver"),
		apiv1:  apiv1,
		gin:    gin.New(),
		tracer: tracer,
		server: &http.Server{
			ReadHeaderTimeout: 3 * time.Second,
		},
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

	// OIDC Endpoints
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "authorize", http.StatusOK, s.endpointAuthorize)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "token", http.StatusOK, s.endpointToken)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "userinfo", http.StatusOK, s.endpointUserInfo)

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
