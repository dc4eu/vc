package apiv1

import (
	"context"
	"vc/internal/issuer/ca"
	"vc/internal/issuer/db"
	"vc/internal/issuer/kv"
	"vc/pkg/logger"
	"vc/pkg/model"
)

// Client holds the public api object
type Client struct {
	ca     *ca.Client
	cfg    *model.Cfg
	db     *db.Service
	kv     *kv.Service
	logger *logger.Log
}

// New creates a new instance of the public api
func New(ctx context.Context, ca *ca.Client, kvService *kv.Service, db *db.Service, cfg *model.Cfg, logger *logger.Log) (*Client, error) {
	c := &Client{
		cfg:    cfg,
		db:     db,
		kv:     kvService,
		logger: logger,
		ca:     ca,
	}

	c.logger.Info("Started")

	return c, nil
}
