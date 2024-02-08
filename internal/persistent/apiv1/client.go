package apiv1

import (
	"context"
	"vc/internal/persistent/db"
	"vc/pkg/kvclient"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

//	@title		Datastore API
//	@version	0.1.0
//	@BasePath	/datastore/api/v1

// Client holds the public api object
type Client struct {
	cfg *model.Cfg
	log *logger.Log
	tp  *trace.Tracer
	kv  *kvclient.Client
	db  *db.Service
}

// New creates a new instance of the public api
func New(ctx context.Context, kv *kvclient.Client, db *db.Service, tp *trace.Tracer, cfg *model.Cfg, logger *logger.Log) (*Client, error) {
	c := &Client{
		cfg: cfg,
		kv:  kv,
		db:  db,
		tp:  tp,
		log: logger,
	}

	c.log.Info("Started")

	return c, nil
}
