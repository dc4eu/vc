package oauth

import (
	"context"
	"vc/internal/apigw/db"
	"vc/pkg/logger"
	"vc/pkg/model"
)

type Client struct {
	cfg *model.Cfg
	db  *db.Service
	log *logger.Log
}

func New(ctx context.Context, cfg *model.Cfg, db *db.Service, log *logger.Log) (*Client, error) {
	client := &Client{
		cfg: cfg,
		db:  db,
		log: log,
	}

	return client, nil
}
