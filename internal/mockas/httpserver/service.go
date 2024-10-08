package httpserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
	"vc/internal/mockas/apiv1"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

// Service is the service object for httpserver
type Service struct {
	config    *model.Cfg
	logger    *logger.Log
	server    *http.Server
	apiv1     Apiv1
	gin       *gin.Engine
	tlsConfig *tls.Config
	tp        *trace.Tracer
}

// New creates a new httpserver service
func New(ctx context.Context, config *model.Cfg, api *apiv1.Client, tracer *trace.Tracer, logger *logger.Log) (*Service, error) {
	s := &Service{
		config: config,
		logger: logger,
		apiv1:  api,
		server: &http.Server{Addr: config.MockAS.APIServer.Addr, ReadHeaderTimeout: 2 * time.Second},
		tp:     tracer,
	}

	switch s.config.Common.Production {
	case true:
		gin.SetMode(gin.ReleaseMode)
	case false:
		gin.SetMode(gin.DebugMode)
	}

	apiValidator, err := helpers.NewValidator()
	if err != nil {
		return nil, err
	}

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
	problem404, err := helpers.Problem404()
	if err != nil {
		return nil, err
	}
	s.gin.NoRoute(func(c *gin.Context) { c.JSON(http.StatusNotFound, problem404) })

	rgRoot := s.gin.Group("/")

	s.regEndpoint(ctx, rgRoot, http.MethodGet, "health", s.endpointStatus)

	rgAPIv1 := rgRoot.Group("api/v1")
	rgMock := rgAPIv1.Group("/mock")
	s.regEndpoint(ctx, rgMock, http.MethodPost, "/next", s.endpointMockNext)
	s.regEndpoint(ctx, rgMock, http.MethodPost, "/bulk", s.endpointMockBulk)

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
		k := fmt.Sprintf("api_endpoint %s:%s%s", method, rg.BasePath(), path)
		ctx, span := s.tp.Start(ctx, k)
		defer span.End()

		res, err := handler(ctx, c)
		if err != nil {
			s.renderContent(ctx, c, 400, gin.H{"error": helpers.NewErrorFromError(err)})
			return
		}

		s.renderContent(ctx, c, 200, res)
	})
}

func (s *Service) renderContent(ctx context.Context, c *gin.Context, code int, data any) {
	ctx, span := s.tp.Start(ctx, "httpserver:renderContent")
	defer span.End()

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
