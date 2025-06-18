package httpserver

import (
	"context"
	"html/template"
	"net/http"
	"vc/internal/apigw/apiv1"
	"vc/internal/apigw/staticembed"
	"vc/pkg/httphelpers"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/trace"

	"github.com/gin-contrib/sessions"

	// Swagger
	_ "vc/docs/apigw"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// Service is the service object for httpserver
type Service struct {
	cfg             *model.Cfg
	log             *logger.Log
	server          *http.Server
	apiv1           Apiv1
	gin             *gin.Engine
	tracer          *trace.Tracer
	eventPublisher  apiv1.EventPublisher
	httpHelpers     *httphelpers.Client
	sessionsOptions sessions.Options
	sessionsEncKey  string
	sessionsAuthKey string
	sessionsName    string
}

// New creates a new httpserver service
func New(ctx context.Context, cfg *model.Cfg, apiv1 *apiv1.Client, tracer *trace.Tracer, eventPublisher apiv1.EventPublisher, log *logger.Log) (*Service, error) {
	s := &Service{
		cfg:             cfg,
		log:             log.New("httpserver"),
		apiv1:           apiv1,
		gin:             gin.New(),
		tracer:          tracer,
		server:          &http.Server{},
		eventPublisher:  eventPublisher,
		sessionsName:    "oauth_user_session",
		sessionsAuthKey: oauth2.GenerateCryptographicNonceWithLength(32),
		sessionsEncKey:  oauth2.GenerateCryptographicNonceWithLength(32),
		sessionsOptions: sessions.Options{
			Path:     "/",
			Domain:   "",
			MaxAge:   900,
			Secure:   false, // TODO(masv): fix this
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
	}

	var err error
	s.httpHelpers, err = httphelpers.New(ctx, s.tracer, s.cfg, s.log)
	if err != nil {
		return nil, err
	}

	// Used in development to avoid bundling static files in the executable.
	// When used, comment the four lines below these ones.
	// s.gin.Static("/static", "./staticembed")
	// s.gin.LoadHTMLFiles("./staticembed/index.html")

	s.gin.StaticFS("/static", http.FS(staticembed.FS))

	f := template.Must(template.New("").ParseFS(staticembed.FS, "index.html"))
	s.gin.SetHTMLTemplate(f)

	rgRoot, err := s.httpHelpers.Server.Default(ctx, s.server, s.gin, s.cfg.APIGW.APIServer.Addr)
	if err != nil {
		return nil, err
	}

	//rgRoot.Use(cors.New(cors.Config{
	//	AllowOrigins:     []string{"https://dc4eu.wwwallet.org", "https://demo.wwwallet.org", "https://dev.wallet.sunet.se"},
	//	AllowMethods:     []string{"GET", "POST", "OPTIONS"},
	//	AllowHeaders:     []string{"Content-Type", "Authorization"},
	//	AllowCredentials: true,
	//	MaxAge:           12 * time.Hour,
	//}))

	rgRestricted, err := s.httpHelpers.Server.Default(ctx, s.server, s.gin, s.cfg.APIGW.APIServer.Addr)
	if err != nil {
		return nil, err
	}

	rgRestricted.Use(s.httpHelpers.Middleware.BasicAuth(ctx, s.cfg.APIGW.APIServer.BasicAuth.Users))

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "nonce", http.StatusOK, s.endpointOIDCNonce)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "credential", http.StatusOK, s.endpointOIDCCredential)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "credential-offer/:credential_offer_uuid", http.StatusOK, s.endpointOIDCredentialOfferURI)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "deferred_credential", http.StatusOK, s.endpointOIDCDeferredCredential)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRestricted, http.MethodPost, "notification", http.StatusNoContent, s.endpointOIDCNotification)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, ".well-known/openid-credential-issuer", http.StatusOK, s.endpointOIDCMetadata)

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, ".well-known/oauth-authorization-server", http.StatusOK, s.endpointOAuth2Metadata)
	rgOAuthSession := rgRoot.Group("")
	rgOAuthSession.Use(s.httpHelpers.Middleware.UserSession(s.sessionsName, s.sessionsAuthKey, s.sessionsEncKey, s.sessionsOptions))
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodPost, "op/par", http.StatusCreated, s.endpointOAuthPar)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodGet, "authorize", http.StatusPermanentRedirect, s.endpointOAuthAuthorize)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodGet, "authorization/consent", http.StatusNotModified, s.endpointOAuthAuthorizationConsent)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodPost, "authorization/consent", http.StatusSeeOther, s.endpointOAuthWalletRedirect)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodPost, "token", http.StatusOK, s.endpointOAuthToken)

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "health", 200, s.endpointHealth)

	rgDocs := rgRoot.Group("/swagger")
	rgDocs.GET("/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	rgAPIv1 := rgRoot.Group("api/v1")

	if s.cfg.APIGW.APIServer.BasicAuth.Enabled {
		rgAPIv1.Use(s.httpHelpers.Middleware.BasicAuth(ctx, s.cfg.APIGW.APIServer.BasicAuth.Users))
	}

	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/upload", http.StatusOK, s.endpointUpload)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/notification", http.StatusOK, s.endpointNotification)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPut, "/document/identity", http.StatusOK, s.endpointAddDocumentIdentity)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodDelete, "/document/identity", http.StatusOK, s.endpointDeleteDocumentIdentity)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodDelete, "/document", http.StatusOK, s.endpointDeleteDocument)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/document/collect_id", http.StatusOK, s.endpointGetDocumentCollectID)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/identity/mapping", http.StatusOK, s.endpointIdentityMapping)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/document/list", http.StatusOK, s.endpointDocumentList)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/document", http.StatusOK, s.endpointGetDocument)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/document/search", http.StatusOK, s.endpointSearchDocuments)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/consent", http.StatusOK, s.endpointAddConsent)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/consent/get", http.StatusOK, s.endpointGetConsent)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/document/revoke", http.StatusOK, s.endpointRevokeDocument)

	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/user/pid", http.StatusOK, s.endpointAddPIDUser)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodPost, "/user/pid/login", http.StatusOK, s.endpointLoginPIDUser)

	// SatosaCredential remove after refactoring
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "credential", http.StatusOK, s.endpointSatosaCredential)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodGet, "/credential/.well-known/jwks", http.StatusOK, s.endpointJWKS)

	// Run http server
	go func() {
		err := s.httpHelpers.Server.ListenAndServe(ctx, s.server, s.cfg.APIGW.APIServer)
		if err != nil {
			s.log.Trace("listen_error", "error", err)
		}
	}()

	s.log.Info("Started")

	return s, nil
}

// Close closing httpserver
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Stopped")
	return nil
}
