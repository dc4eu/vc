package apiv1

import (
	"context"
	"vc/internal/wallet/db"
	"vc/pkg/datastoreclient"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

// Client holds the public api object
type Client struct {
	cfg             *model.Cfg
	db              *db.Service
	log             *logger.Log
	tracer          *trace.Tracer
	datastoreClient *datastoreclient.Client
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, tracer *trace.Tracer, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:    cfg,
		db:     db,
		log:    log.New("apiv1"),
		tracer: tracer,
	}


	c.log.Info("Started")

	return c, nil
}
