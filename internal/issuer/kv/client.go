package kv

import (
	"context"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/redis/go-redis/v9"
)

// Service holds the kv object
type Service struct {
	redisClient *redis.Client
	cfg         *model.Cfg
	log         *logger.Logger

	Doc *Doc
}

// New creates a new instance of kv
func New(ctx context.Context, cfg *model.Cfg, log *logger.Logger) (*Service, error) {
	c := &Service{
		cfg: cfg,
	}

	c.redisClient = redis.NewClient(&redis.Options{
		Addr:     cfg.Issuer.KeyValue.Addr,
		Password: "",
		DB:       cfg.Issuer.KeyValue.DB,
	})

	c.Doc = &Doc{
		client: c,
		key:    "doc:%s:%s",
	}

	return c, nil
}

// Close closes the connection to the database
func (c *Service) Close(ctx context.Context) error {
	return c.redisClient.Close()
}
