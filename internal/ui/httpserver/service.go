package httpserver

import (
	"context"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"net/http"
	"reflect"
	"strings"
	"vc/internal/ui/apiv1"
	"vc/pkg/trace"

	"time"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/gin-gonic/gin"
)

// Service is the service object for httpserver
type Service struct {
	config        *model.Cfg
	logger        *logger.Log
	tp            *trace.Tracer
	server        *http.Server
	apiv1         Apiv1
	gin           *gin.Engine
	sessionConfig *sessionConfig
}

// sessionConfig... values is also used for the session cookie
type sessionConfig struct {
	//if name is changed, the web (javascript) must also be updated with the new name
	name                       string
	inactivityTimeoutInSeconds int
	path                       string
	httpOnly                   bool
	secure                     bool
	sameSite                   http.SameSite
	usernameKey                string
	loggedInTimeKey            string
}

// New creates a new httpserver service
func New(ctx context.Context, config *model.Cfg, api *apiv1.Client, tracer *trace.Tracer, logger *logger.Log) (*Service, error) {
	s := &Service{
		config: config,
		logger: logger,
		tp:     tracer,
		apiv1:  api,
		server: &http.Server{
			Addr:              config.UI.APIServer.Addr,
			ReadTimeout:       time.Second * 5,
			WriteTimeout:      time.Second * 30,
			IdleTimeout:       time.Second * 90,
			ReadHeaderTimeout: time.Second * 2,
		},
		sessionConfig: &sessionConfig{
			name:                       "vc_ui_auth_session",
			inactivityTimeoutInSeconds: 300,
			path:                       "/",
			httpOnly:                   true,
			secure:                     config.UI.APIServer.TLS.Enabled,
			sameSite:                   http.SameSiteStrictMode,
			usernameKey:                "username_key",
			loggedInTimeKey:            "logged_in_time_key",
		},
	}

	switch s.config.Common.Production {
	case true:
		gin.SetMode(gin.ReleaseMode)
	case false:
		gin.SetMode(gin.DebugMode)
	}

	apiValidator := validator.New()
	apiValidator.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
	binding.Validator = &defaultValidator{
		Validate: apiValidator,
	}

	s.gin = gin.New()
	s.server.Handler = s.gin

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

	s.gin.Static("/static", "./static")
	s.gin.LoadHTMLFiles("./static/index.html")
	s.gin.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	rgRoot := s.gin.Group("/")
	s.regEndpoint(ctx, rgRoot, http.MethodPost, "login", s.endpointLogin)
	s.regEndpoint(ctx, rgRoot, http.MethodGet, "health", s.endpointStatus)

	rgSecure := rgRoot.Group("secure", s.middlewareAuthRequired(ctx))
	s.regEndpoint(ctx, rgSecure, http.MethodDelete, "logout", s.endpointLogout)
	s.regEndpoint(ctx, rgSecure, http.MethodGet, "user", s.endpointUser)

	rgAPIGW := rgSecure.Group("apigw")
	s.regEndpoint(ctx, rgAPIGW, http.MethodGet, "health", s.endpointAPIGWStatus)
	s.regEndpoint(ctx, rgAPIGW, http.MethodPost, "portal", s.endpointPortal)
	s.regEndpoint(ctx, rgAPIGW, http.MethodPost, "upload", s.endpointUpload)

	rgMockAS := rgSecure.Group("mockas")
	s.regEndpoint(ctx, rgMockAS, http.MethodPost, "mock/next", s.endpointMockNext)

	// Run http server
	go func() {
		err := s.server.ListenAndServe()
		if err != nil {
			s.logger.New("http").Trace("listen_error", "error", err)
		}
	}()

	s.logger.Info("started")

	return s, nil
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
