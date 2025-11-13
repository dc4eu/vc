package httpserver

import (
	"context"
	"net/http"
	"time"
	"vc/internal/verifier/apiv1"
	"vc/internal/verifier/notify"
	"vc/pkg/httphelpers"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/trace"

	"github.com/gin-contrib/sessions"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/gin-gonic/gin"
)

// Service is the service object for httpserver
type Service struct {
	cfg             *model.Cfg
	log             *logger.Log
	server          *http.Server
	apiv1           Apiv1
	gin             *gin.Engine
	tracer          *trace.Tracer
	httpHelpers     *httphelpers.Client
	notify          *notify.Service
	sessionsOptions sessions.Options
	sessionsEncKey  string
	sessionsAuthKey string
	sessionsName    string
}

// New creates a new httpserver service
func New(ctx context.Context, cfg *model.Cfg, apiv1 *apiv1.Client, notify *notify.Service, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	s := &Service{
		cfg:    cfg,
		log:    log.New("httpserver"),
		apiv1:  apiv1,
		gin:    gin.New(),
		notify: notify,
		tracer: tracer,
		server: &http.Server{
			ReadHeaderTimeout: 3 * time.Second,
		},
		sessionsName:    "verifier_user_session",
		sessionsAuthKey: oauth2.GenerateCryptographicNonceFixedLength(32),
		sessionsEncKey:  oauth2.GenerateCryptographicNonceFixedLength(32),
		sessionsOptions: sessions.Options{
			Path:     "/",
			Domain:   "",
			MaxAge:   900,
			Secure:   false,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
	}

	if s.cfg.Verifier.APIServer.TLS.Enabled {
		s.sessionsOptions.Secure = true
		//s.sessionsOptions.SameSite = http.SameSiteStrictMode
	}

	var err error
	s.httpHelpers, err = httphelpers.New(ctx, s.tracer, s.cfg, s.log)
	if err != nil {
		return nil, err
	}

	rgRoot, err := s.httpHelpers.Server.Default(ctx, s.server, s.gin, s.cfg.Verifier.APIServer.Addr)
	if err != nil {
		return nil, err
	}

	// templating functions
	s.gin.SetFuncMap(template.FuncMap{
		"toJSON": func(v any) string {
			b, _ := json.MarshalIndent(v, "", "  ")
			return string(b)
		},
	})

	s.gin.Static("/static", "./static")
	s.gin.LoadHTMLGlob("./static/*.html")

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "/", http.StatusOK, s.endpointIndex)

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "health", http.StatusOK, s.endpointHealth)

	// oauth2
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, ".well-known/oauth-authorization-server", http.StatusOK, s.endpointOAuthMetadata)

	rgOAuthSession := rgRoot.Group("")
	rgOAuthSession.Use(s.httpHelpers.Middleware.UserSession(s.sessionsName, s.sessionsAuthKey, s.sessionsEncKey, s.sessionsOptions))
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodPost, "op/par", http.StatusCreated, s.endpointOAuthPar)

	sgVerification := rgOAuthSession.Group("/verification")
	s.httpHelpers.Server.RegEndpoint(ctx, sgVerification, http.MethodGet, "request-object", http.StatusOK, s.endpointVerificationRequestObject)
	s.httpHelpers.Server.RegEndpoint(ctx, sgVerification, http.MethodPost, "direct_post", http.StatusOK, s.endpointVerificationDirectPost)
	s.httpHelpers.Server.RegEndpoint(ctx, sgVerification, http.MethodGet, "callback", http.StatusOK, s.endpointVerificationCallback)

	rgUI := rgOAuthSession.Group("/ui")
	s.httpHelpers.Server.RegEndpoint(ctx, rgUI, http.MethodPost, "/interaction", http.StatusOK, s.endpointUIInteraction)
	s.httpHelpers.Server.RegEndpoint(ctx, rgUI, http.MethodGet, "/notify", http.StatusOK, s.endpointUINotify)
	s.httpHelpers.Server.RegEndpoint(ctx, rgUI, http.MethodGet, "/metadata", http.StatusOK, s.endpointUIMetadata)

	rgDocs := rgRoot.Group("/swagger")
	rgDocs.GET("/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

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
