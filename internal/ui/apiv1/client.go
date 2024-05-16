package apiv1

import (
	"context"
	"vc/internal/ui/vcclient"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

// Client holds the public api object
type Client struct {
	cfg     *model.Cfg
	tp      *trace.Tracer
	log     *logger.Log
	apigwc  *vcclient.APIGWClient
	mockasc *vcclient.MockASClient
}

func New(ctx context.Context, cfg *model.Cfg, apigwc *vcclient.APIGWClient, mockasc *vcclient.MockASClient, tp *trace.Tracer, log *logger.Log) (*Client, error) {
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
