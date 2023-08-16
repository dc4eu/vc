package httpserver

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"time"
	"vc/internal/datastore/apiv1"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

// Service is the service object for httpserver
type Service struct {
	config *model.Cfg
	logger *logger.Log
	server *http.Server
	apiv1  Apiv1
	gin    *gin.Engine
}

// New creates a new httpserver service
func New(ctx context.Context, config *model.Cfg, api *apiv1.Client, logger *logger.Log) (*Service, error) {
	s := &Service{
		config: config,
		logger: logger,
		apiv1:  api,
		server: &http.Server{Addr: config.Datastore.APIServer.Addr},
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

	rgAPIV1 := rgRoot.Group("api/v1")

	rgEHIC := rgAPIV1.Group("/ehic")
	s.regEndpoint(ctx, rgEHIC, "POST", "/upload", s.endpointEHICUpload)
	s.regEndpoint(ctx, rgEHIC, "GET", "/:upload_id", s.endpointEHICID)

	rgPDA1 := rgAPIV1.Group("/pda1")
	s.regEndpoint(ctx, rgPDA1, "POST", "/upload", s.endpointPDA1Upload)
	s.regEndpoint(ctx, rgPDA1, "GET", "/:upload_id", s.endpointPDA1ID)
	s.regEndpoint(ctx, rgPDA1, "POST", "/", s.endpointPDA1Search)

	s.regEndpoint(ctx, rgAPIV1, "POST", "/upload", s.endpointGenericUpload)
	s.regEndpoint(ctx, rgAPIV1, "POST", "/list", s.endpointGenericList)
	s.regEndpoint(ctx, rgAPIV1, "POST", "/document", s.endpointGenericDocument)
	s.regEndpoint(ctx, rgAPIV1, "POST", "/qr", s.endpointGenericQR)

	rgLadok := rgAPIV1.Group("/ladok")
	s.regEndpoint(ctx, rgLadok, "POST", "/upload", s.endpointLadokUpload)
	s.regEndpoint(ctx, rgLadok, "GET", "/:upload_id", s.endpointLadokID)

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
