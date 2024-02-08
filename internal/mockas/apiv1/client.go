package apiv1

import (
	"context"
	"net/http"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

//	@title		Issuer API
//	@version	0.1.0
//	@BasePath	/issuer/api/v1

// Client holds the public api object
type Client struct {
	cfg        *model.Cfg
	log        *logger.Log
	tp         *trace.Tracer
	httpClient *http.Client

	PDA1 *PDA1Service
	EHIC *EHICService
}

// New creates a new instance of the public api
func New(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, logger *logger.Log) (*Client, error) {
	c := &Client{
		cfg:        cfg,
		log:        logger,
		tp:         tracer,
		httpClient: &http.Client{},
	}

	c.PDA1 = &PDA1Service{
		Client: c,
	}
	c.EHIC = &EHICService{
		Client: c,
	}

	c.log.Info("Started")

	return c, nil
}
