package apiv1

import (
	"context"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

// Client holds the public api object
type Client struct {
	cfg     *model.Cfg
	tp      *trace.Tracer
	log     *logger.Log
	apigwc  *APIGWClient
	mockasc *MockASClient
}

func New(ctx context.Context, cfg *model.Cfg, apigwc *APIGWClient, mockasc *MockASClient, tp *trace.Tracer, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:     cfg,
		tp:      tp,
		log:     log,
		apigwc:  apigwc,
		mockasc: mockasc,
	}

	c.log.Info("Started")

	return c, nil
}
