package apiv1

import (
	"context"
	"vc/internal/registry/tree"
	"vc/pkg/logger"
	"vc/pkg/model"
)

// Client holds the public api object
type Client struct {
	cfg  *model.Cfg
	log  *logger.Log
	tree *tree.Service
}

//	@title		Registry API
//	@version	0.1.0
//	@BasePath	/api/v1

// New creates a new instance of the public api
func New(ctx context.Context, cfg *model.Cfg, tree *tree.Service, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:  cfg,
		log:  log.New("apiv1"),
		tree: tree,
	}
	c.log.Info("Started")

	return c, nil
}
