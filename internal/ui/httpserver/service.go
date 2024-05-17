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

// TODO: flytta konstanter till Service structen MEN "I Go finns det inget direkt sätt att ha statiska fält i en struct som i vissa andra programmeringsspråk. Alla fält i en struct i Go är dynamiska, vilket betyder att de är specifika för varje instans av structen."
const (
	/* session... constants is also used for the session cookie */
	sessionName                       = "vc_ui_auth_session" //if changed, the web (javascript) must also be updated with the new name
	sessionInactivityTimeoutInSeconds = 300                  // after this time with inactivity the session is auto removed from session storage - also the MaxAge value for the cookie
	sessionPath                       = "/"
	sessionHttpOnly                   = true
	//TODO: sätt värde baserat på om tls är aktiverat eller ej via config
	sessionSecure          = false //TODO: activate for https
	sessionSameSite        = http.SameSiteStrictMode
	sessionUsernameKey     = "username_key" //key to retrive the username for the logged in user from the session (not stored in any cookie)
	sessionLoggedInTimeKey = "logged_in_time"
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
		server: &http.Server{
			Addr: config.UI.APIServer.Addr,
			/* TODO: sätt och ta in via config
			ReadTimeout	Den maximala tiden som servern väntar på att läsa hela förfrågan (inklusive kroppen). Skyddar mot långsamma klienter.
			WriteTimeout	Den maximala tiden som servern väntar på att skriva svaret till klienten. Skyddar mot långsamma nätverk och klienter.
			IdleTimeout	Den maximala tiden som en anslutning kan vara inaktiv innan den stängs. Skyddar mot att hålla anslutningar öppna för länge utan aktivitet.
			ReadHeaderTimeout	Den maximala tiden som servern väntar på att läsa HTTP-rubrikerna. Skyddar mot långsamma klienter vid början av en anslutning.
			MaxHeaderBytes	Den maximala storleken på HTTP-rubrikerna i byte. Skyddar mot attacker med stora rubriker som kan överbelasta servern.
			*/
			ReadHeaderTimeout: 2 * time.Second},
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

	//TODO: flytta till config
	s.gin = gin.New()
	s.server.Handler = s.gin
	/* TODO: sätt och ta in via config
	ReadTimeout	Den maximala tiden som servern väntar på att läsa hela förfrågan (inklusive kroppen). Skyddar mot långsamma klienter.
	WriteTimeout	Den maximala tiden som servern väntar på att skriva svaret till klienten. Skyddar mot långsamma nätverk och klienter.
	IdleTimeout	Den maximala tiden som en anslutning kan vara inaktiv innan den stängs. Skyddar mot att hålla anslutningar öppna för länge utan aktivitet.
	ReadHeaderTimeout	Den maximala tiden som servern väntar på att läsa HTTP-rubrikerna. Skyddar mot långsamma klienter vid början av en anslutning.
	MaxHeaderBytes	Den maximala storleken på HTTP-rubrikerna i byte. Skyddar mot attacker med stora rubriker som kan överbelasta servern.
	*/
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
	s.regEndpoint(ctx, rgRoot, http.MethodPost, "/login", s.endpointLogin)
	s.regEndpoint(ctx, rgRoot, http.MethodGet, "/health", s.endpointStatus)

	rgSecure := rgRoot.Group("secure")
	rgSecure.Use(s.authRequired)
	s.regEndpoint(ctx, rgSecure, http.MethodDelete, "/logout", s.endpointLogout)
	s.regEndpoint(ctx, rgSecure, http.MethodGet, "/user", s.endpointUser)

	///apigw
	s.regEndpoint(ctx, rgSecure, http.MethodGet, "/apigw/health", s.endpointAPIGWStatus)
	s.regEndpoint(ctx, rgSecure, http.MethodPost, "/apigw/portal", s.endpointPortal)

	//mockas
	s.regEndpoint(ctx, rgSecure, http.MethodPost, "/mockas/mock/next", s.endpointMockNext)

	// Run http server
	go func() {
		//TODO: add tls support (see service apigw) + sessionSecure must be set to true
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
