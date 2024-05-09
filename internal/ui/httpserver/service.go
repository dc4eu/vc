package httpserver

import (
	"context"
	"github.com/gin-contrib/sessions"
	"net/http"
	"vc/internal/ui/apiv1"
	"vc/pkg/trace"

	//"reflect"
	//"strings"
	"time"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"

	//_ "vc/docs/datastore"

	"github.com/gin-gonic/gin"
)

const (
	/* session... constants is also used for the session cookie */
	sessionName = "vc_ui_auth_session" //if changed, the web (javascript) must also be updated with the new name
	//sessionKey                        = "sessionkey"
	sessionInactivityTimeoutInSeconds = 300 // after this time with inactivity the session is auto removed from session storage - also the MaxAge value for the cookie
	sessionPath                       = "/"
	sessionHttpOnly                   = true
	sessionSecure                     = false //TODO: activate for https
	sessionSameSite                   = http.SameSiteStrictMode
	sessionUsernameKey                = "username_key" //key to retrive the username for the logged in user from the session (not stored in any cookie)
	sessionLoggedInTimeKey            = "logged_in_time"
)

// Service is the service object for httpserver
type Service struct {
	config *model.Cfg
	logger *logger.Log
	tp     *trace.Tracer
	server *http.Server
	apiv1  Apiv1
	gin    *gin.Engine
}

// New creates a new httpserver service
func New(ctx context.Context, config *model.Cfg, api *apiv1.Client, tracer *trace.Tracer, logger *logger.Log) (*Service, error) {
	s := &Service{
		config: config,
		logger: logger,
		tp:     tracer,
		apiv1:  api,
		server: &http.Server{Addr: config.UI.APIServer.Addr, ReadHeaderTimeout: 2 * time.Second},
	}

	switch s.config.Common.Production {
	case true:
		gin.SetMode(gin.ReleaseMode)
	case false:
		gin.SetMode(gin.DebugMode)
	}

	//apiValidator := validator.New()
	//apiValidator.RegisterTagNameFunc(func(fld reflect.StructField) string {
	//	name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
	//
	//	if name == "-" {
	//		return ""
	//	}
	//
	//	return name
	//})
	//binding.Validator = &defaultValidator{
	//	Validate: apiValidator,
	//}

	s.gin = gin.New()
	s.server.Handler = s.gin
	s.server.ReadTimeout = time.Second * 5
	s.server.WriteTimeout = time.Second * 30
	s.server.IdleTimeout = time.Second * 90

	// Middlewares
	s.gin.Use(s.middlewareTraceID(ctx))
	s.gin.Use(s.middlewareDuration(ctx))
	s.gin.Use(s.middlewareLogger(ctx))
	s.gin.Use(s.middlewareCrash(ctx))
	s.gin.Use(s.middlewareGzip(ctx))
	s.gin.Use(s.middlewareUserSession(ctx, s.config))

	problem404, err := helpers.Problem404()
	if err != nil {
		return nil, err
	}
	s.gin.NoRoute(func(c *gin.Context) { c.JSON(http.StatusNotFound, problem404) })

	// Static route
	s.gin.Static("/static", "./static")
	s.gin.LoadHTMLFiles("./static/index.html")
	s.gin.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	rgRoot := s.gin.Group("/")
	s.regEndpoint(ctx, rgRoot, http.MethodPost, "login", s.login)

	//rgDocs := rgRoot.Group("/swagger")
	//rgDocs.GET("/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	rgSecure := rgRoot.Group("secure")
	rgSecure.Use(s.authRequired)
	s.regEndpoint(ctx, rgSecure, http.MethodGet, "health/ui", s.endpointStatus)
	s.regEndpoint(ctx, rgSecure, http.MethodDelete, "/logout", s.logout)
	rgSecure.GET("/user", getUserHandler)

	//s.regEndpoint(ctx, rgAPIV1, http.MethodPost, "/upload", s.endpointUpload)
	//s.regEndpoint(ctx, rgAPIV1, http.MethodPost, "/document", s.endpointGetDocument)
	//s.regEndpoint(ctx, rgAPIV1, http.MethodPost, "/document/collect_code", s.endpointGetDocumentByCollectCode)
	//s.regEndpoint(ctx, rgAPIV1, http.MethodPost, "/id_mapping", s.endpointIDMapping)
	//s.regEndpoint(ctx, rgAPIV1, http.MethodPost, "/metadata", s.endpointListMetadata)
	//s.regEndpoint(ctx, rgAPIV1, http.MethodPost, "/portal", s.endpointPortal)

	// Run http server
	go func() {
		//TODO: add tls support (see service apigw)
		err := s.server.ListenAndServe()
		if err != nil {
			s.logger.New("http").Trace("listen_error", "error", err)
		}
	}()

	s.logger.Info("started")

	return s, nil
}

func getUserHandler(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get(sessionUsernameKey)
	loggedInTime := session.Get(sessionLoggedInTimeKey)
	c.JSON(http.StatusOK, gin.H{"user": user, "logged_in_time": loggedInTime})
}

func (s *Service) regEndpoint(ctx context.Context, rg *gin.RouterGroup, method, path string, handler func(context.Context, *gin.Context) (interface{}, error)) {
	rg.Handle(method, path, func(c *gin.Context) {
		res, err := handler(ctx, c)
		if err != nil {
			renderContent(c, 400, gin.H{"error": helpers.NewErrorFromError(err)})
			return
		}

		renderContent(c, 200, res)
	})
}

func renderContent(c *gin.Context, code int, data interface{}) {
	switch c.NegotiateFormat(gin.MIMEJSON, "*/*") {
	case gin.MIMEJSON:
		c.JSON(code, data)
	case "*/*": // curl
		c.JSON(code, data)
	default:
		c.JSON(406, gin.H{"error": helpers.NewErrorDetails("not_acceptable", "Accept header is invalid. It should be \"application/json\".")})
	}
}

// Close closing httpserver
func (s *Service) Close(ctx context.Context) error {
	s.logger.Info("Quit")
	return nil
}
