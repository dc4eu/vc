package apiv1

import (
	"context"
	"vc/pkg/logger"
	"vc/pkg/model"
)

// Client holds the public api object
type Client struct {
	config *model.Cfg
	logger *logger.Log
}

// New creates a new instance of the public api
func New(ctx context.Context, config *model.Cfg, logger *logger.Log) (*Client, error) {
	c := &Client{
		config: config,
		logger: logger,
	}

	c.logger.Info("Started")

	return c, nil
}
