package httpserver

import (
	"context"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"net/http"
	"vc/internal/verifier/apiv1"
	"vc/pkg/httphelpers"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

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
			Secure:   cfg.UI.APIServer.TLS.Enabled,
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

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "health", s.endpointHealth)

	//openid4vp
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "qrcode", s.endpointQRCode)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "authorize", s.endpointGetAuthorizationRequest)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "callback/direct_post_jwt/:session_id/:callback_id", s.endpointCallback)

	//TODO: behövs även en mer allmän status endpoint för en pågående verifiering som inte bara stödjer web session
	//TODO: behövs https://<domain>/.well-known/openid-configuration + "jwks_uri:":"https://<domain>/oauth/jwks" endpoints???

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "verificationresult", s.endpointGetVerificationResult)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodDelete, "quitvpflow", s.endpointQuitVPFlow)

	// for dev purpose only
	//TODO: OBS! nedan endpoint behöver säkerhet innan mer känsliga nycklar och/eller data börjar användas (tillåts dock ej redan om vc satt till production)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "debug/vp-flow", s.endpointGetVPFlowDebugInfo)

	//deprecated: to be removed later
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "verify", s.endpointVerifyCredential)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "decode", s.endpointDecodeCredential)

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
