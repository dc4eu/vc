package apiv1

import (
	"context"
	"vc/pkg/logger"
	"vc/pkg/model"
)

// Client holds the public api object
type Client struct {
	cfg *model.Cfg
	log *logger.Log
}

// New creates a new instance of the public api
func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg: cfg,
		log: log.New("apiv1"),
	}

	c.log.Info("Started")

	return c, nil
}
