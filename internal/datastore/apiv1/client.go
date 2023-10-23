package apiv1

import (
	"context"
	"vc/internal/datastore/db"
	"vc/pkg/logger"
	"vc/pkg/model"
)

//	@title		Datastore API
//	@version	0.1.0
//	@BasePath	/datastore/api/v1

// Client holds the public api object
type Client struct {
	cfg *model.Cfg
	db  *db.Service
	log *logger.Log
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, cfg *model.Cfg, logger *logger.Log) (*Client, error) {
	c := &Client{
		cfg: cfg,
		db:  db,
		log: logger,
	}

	c.log.Info("Started")

	return c, nil
}
