package apiv1

import (
	"context"
	"wallet/pkg/logger"
	"wallet/pkg/model"
)

// Client holds the public api object
type Client struct {
	config *model.Cfg
	logger *logger.Logger
}

// New creates a new instance of the public api
func New(ctx context.Context, config *model.Cfg, logger *logger.Logger) (*Client, error) {
	c := &Client{
		config: config,
		logger: logger,
	}

	c.logger.Info("Started")

	return c, nil
}
