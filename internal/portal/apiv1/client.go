package apiv1

import (
	"context"
	"vc/pkg/datastoreclient"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

// Client holds the public api object
type Client struct {
	cfg    *model.Cfg
	log    *logger.Log
	tracer *trace.Tracer

	apigwClient *datastoreclient.Client
}

// New creates a new instance of the public api
func New(ctx context.Context, tracer *trace.Tracer, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:    cfg,
		tracer: tracer,
		log:    log.New("apiv1"),
	}

	var err error
	c.apigwClient, err = datastoreclient.New(&datastoreclient.Config{URL: cfg.Portal.ApigwApiServer.Addr})
	if err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}
