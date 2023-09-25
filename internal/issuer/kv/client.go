package kv

import (
	"context"
	"time"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/redis/go-redis/v9"
)

// Service holds the kv object
type Service struct {
	redisClient *redis.Client
	cfg         *model.Cfg
	log         *logger.Log
	probeStore  *model.ProbeStore

	Doc *Doc
}

// New creates a new instance of kv
func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	c := &Service{
		cfg:        cfg,
		log:        log,
		probeStore: &model.ProbeStore{},
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

	c.log.Info("Started")

	return c, nil
}

// Status returns the status of the database
func (c *Service) Status(ctx context.Context) *model.Probe {
	if time.Now().Before(c.probeStore.NextCheck) {
		return c.probeStore.PreviousResult
	}
	probe := &model.Probe{
		Name:          "kv",
		Healthy:       true,
		Message:       "OK",
		LastCheckedTS: time.Now(),
	}

	_, err := c.redisClient.Ping(ctx).Result()
	if err != nil {
		probe.Message = err.Error()
		probe.Healthy = false
	}
	c.probeStore.PreviousResult = probe
	c.probeStore.NextCheck = time.Now().Add(time.Second * 10)

	return probe
}

// Close closes the connection to the database
func (c *Service) Close(ctx context.Context) error {
	return c.redisClient.Close()
}
