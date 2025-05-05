package httpserver

import (
	"context"
	"net/http"
	"vc/internal/verifier/apiv1"
	"vc/pkg/httphelpers"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/gin-gonic/gin"
)

// Service is the service object for httpserver
type Service struct {
	cfg         *model.Cfg
	log         *logger.Log
	server      *http.Server
	apiv1       Apiv1
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
		server: &http.Server{},
	}

	var err error
	s.httpHelpers, err = httphelpers.New(ctx, s.tracer, s.cfg, s.log)
	if err != nil {
		return nil, err
	}

	VerifierWebEnabled := true //TODO: läs in via cfg
	if VerifierWebEnabled {
		// extra middlewares (MUST be declared before Server.Default)
		s.gin.Use(s.httpHelpers.Middleware.Gzip(ctx))

		//TODO: refactorisera och flytta in nedan till någon middleware struct inkl. fixa egna properties för allt som ska vara dynamiskt
		store := cookie.NewStore([]byte(cfg.UI.SessionCookieAuthenticationKey), []byte(cfg.UI.SessionStoreEncryptionKey))
		store.Options(sessions.Options{
			Path:     "/",
			MaxAge:   600,
			Secure:   cfg.Verifier.APIServer.TLS.Enabled,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		s.gin.Use(sessions.Sessions("vp_flow_web_session", store))
	}

	rgRoot, err := s.httpHelpers.Server.Default(ctx, s.server, s.gin, s.cfg.Verifier.APIServer.Addr)
	if err != nil {
		return nil, err
	}

	if VerifierWebEnabled {
		s.gin.Static("/static", "./static")
		s.gin.LoadHTMLFiles("./static/index.html")
		s.gin.GET("/", func(c *gin.Context) {
			c.HTML(http.StatusOK, "index.html", nil)
		})
	}

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "health", http.StatusOK, s.endpointHealth)

	//openid4vp
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "qr-code", http.StatusOK, s.endpointQRCode)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "authorize", http.StatusOK, s.endpointGetAuthorizationRequest)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "callback/direct-post-jwt/:session_id/:callback_id", http.StatusOK, s.endpointCallback)

	//openid4vp-web
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "verificationresult", http.StatusOK, s.endpointGetVerificationResult)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodDelete, "quitvpflow", http.StatusOK, s.endpointQuitVPFlow)

	//vp-datastore
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "vp-datastore/verification-records", http.StatusOK, s.endpointPaginatedVerificationRecords)

	// for dev purpose only
	//TODO: OBS! nedan endpoint behöver säkerhet innan mer känsliga nycklar och/eller data börjar användas (tillåts dock ej redan om vc satt till production)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "debug/vp-flow", http.StatusOK, s.endpointGetVPFlowDebugInfo)

	//TODO: swagger är inte aktiverat i web_worker för docker - hantera att verifier lär behöva swagger samtidigt som den stödjer web (OBS! ui samt portal har ingen swagger alls)
	rgDocs := rgRoot.Group("/swagger")
	rgDocs.GET("/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	rgAPIv1 := rgRoot.Group("api/v1")

	if s.cfg.APIGW.APIServer.BasicAuth.Enabled {
		rgAPIv1.Use(s.httpHelpers.Middleware.BasicAuth(ctx, s.cfg.APIGW.APIServer.BasicAuth.Users))
	}

	// Run http server
	go func() {
		err := s.httpHelpers.Server.ListenAndServe(ctx, s.server, s.cfg.Verifier.APIServer)
		if err != nil {
			s.log.Trace("listen_error", "error", err)
		}
	}()

	s.log.Info("Started")

	return s, nil
}

// Close closing httpserver
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Stopping")
	return nil
}
