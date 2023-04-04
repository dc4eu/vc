package apiv1

import (
	"context"
	"wallet/internal/issuer/ca"
	"wallet/internal/issuer/db"
	"wallet/pkg/logger"
	"wallet/pkg/model"
)

// Client holds the public api object
type Client struct {
	sunetCA *ca.Client
	cfg     *model.Cfg
	db      db.DB
	logger  *logger.Logger
}

// New creates a new instance of the public api
func New(ctx context.Context, ca *ca.Client, db *db.Service, cfg *model.Cfg, logger *logger.Logger) (*Client, error) {
	c := &Client{
		cfg:    cfg,
		db:     db,
		logger: logger,
	}

	c.logger.Info("Started")

	return c, nil
}
