package apiv1

import (
	"context"
	"vc/internal/persistent/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

//	@title		Datastore API
//	@version	0.1.0
//	@BasePath	/datastore/api/v1

// Client holds the public api object
type Client struct {
	cfg    *model.Cfg
	log    *logger.Log
	tracer *trace.Tracer
	db     *db.Service
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, tracer *trace.Tracer, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:    cfg,
		db:     db,
		tracer: tracer,
		log:    log.New("apiv1"),
	}

	c.log.Info("Started")

	return c, nil
}
