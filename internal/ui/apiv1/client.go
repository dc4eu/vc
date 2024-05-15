package apiv1

import (
	"context"
	"vc/internal/ui/vcclient"
	"vc/pkg/logger"
	"vc/pkg/model"
)

//	@title		UI API
//	@version	0.1.0
//	@BasePath	/api/v1

// Client holds the public api object
type Client struct {
	cfg     *model.Cfg
	log     *logger.Log
	apigwc  *vcclient.APIGWClient
	mockasc *vcclient.MockASClient
}

// New creates a new instance of the public api
func New(ctx context.Context, cfg *model.Cfg, apigwc *vcclient.APIGWClient, mockasc *vcclient.MockASClient, logger *logger.Log) (*Client, error) {
	c := &Client{
		cfg:     cfg,
		log:     logger,
		apigwc:  apigwc,
		mockasc: mockasc,
	}

	c.log.Info("Started")

	return c, nil
}
