package apiv1

import (
	"context"
	"vc/internal/registry/tree"
	"vc/pkg/logger"
	"vc/pkg/model"
)

// Client holds the public api object
type Client struct {
	cfg    *model.Cfg
	logger *logger.Log
	tree   *tree.Service
}

//	@title		Registry API
//	@version	0.1.0
//	@BasePath	/registry/api/v1

// New creates a new instance of the public api
func New(ctx context.Context, cfg *model.Cfg, tree *tree.Service, logger *logger.Log) (*Client, error) {
	c := &Client{
		cfg:    cfg,
		logger: logger,
		tree:   tree,
	}
	c.logger.Info("Started")

	return c, nil
}
