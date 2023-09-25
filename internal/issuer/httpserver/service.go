package httpserver

import (
	"context"
	"net/http"
	"time"
	"vc/internal/issuer/apiv1"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

type routerGroup struct {
	apiv1 *gin.RouterGroup
}

// Service is the service object for httpserver
type Service struct {
	config      *model.Cfg
	logger      *logger.Log
	server      *http.Server
	apiv1       Apiv1
	gin         *gin.Engine
	routerGroup routerGroup
}

// New creates a new httpserver service
func New(ctx context.Context, config *model.Cfg, api *apiv1.Client, logger *logger.Log) (*Service, error) {
	s := &Service{
		config: config,
		logger: logger,
		apiv1:  api,
		server: &http.Server{Addr: config.Issuer.APIServer.Addr},
	}

	switch s.config.Common.Production {
	case true:
		gin.SetMode(gin.ReleaseMode)
	case false:
		gin.SetMode(gin.DebugMode)
	}

	apiValidator := validator.New()
	binding.Validator = &defaultValidator{
		Validate: apiValidator,
	}

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
	s.gin.NoRoute(func(c *gin.Context) {
		status := http.StatusNotFound
		p := helpers.Problem404()
		c.JSON(status, gin.H{"error": p, "data": nil})
	})
	rgRoot := s.gin.Group("/")
	s.regEndpoint(ctx, rgRoot, http.MethodGet, "health", s.endpointStatus)

	rgAPIv1 := rgRoot.Group("api/v1", gin.BasicAuth(s.config.Common.BasicAuth))
	rgAPIv1.Use(s.middlewareAuthLog(ctx))

	s.regEndpoint(ctx, rgAPIv1, http.MethodPost, "/get", s.endpointGenericGet)

	rgLadokPDFv1 := rgAPIv1.Group("/ladok/pdf")
	s.regEndpoint(ctx, rgLadokPDFv1, http.MethodPost, "/sign", s.endpointSignPDF)
	s.regEndpoint(ctx, rgLadokPDFv1, http.MethodPost, "/validate", s.endpointValidatePDF)
	s.regEndpoint(ctx, rgLadokPDFv1, http.MethodGet, "/:transaction_id", s.endpointGetSignedPDF)
	s.regEndpoint(ctx, rgLadokPDFv1, http.MethodPut, "/revoke/:transaction_id", s.endpointPDFRevoke)

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

		status := 200

		if err != nil {
			status = 400
		}

		renderContent(c, status, gin.H{"data": res, "error": helpers.NewErrorFromError(err)})
	})
}

func renderContent(c *gin.Context, code int, data interface{}) {
	switch c.NegotiateFormat(gin.MIMEJSON, "*/*") {
	case gin.MIMEJSON:
		c.JSON(code, data)
	case "*/*": // curl
		c.JSON(code, data)
	default:
		c.JSON(406, gin.H{"data": nil, "error": helpers.NewErrorDetails("not_acceptable", "Accept header is invalid. It should be \"application/json\".")})
	}
}

// Close closing httpserver
func (s *Service) Close(ctx context.Context) error {
	s.logger.Info("Quit")
	return nil
}
