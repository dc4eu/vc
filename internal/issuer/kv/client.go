package kv

import (
	"context"
	"time"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/pkg/logger"
	"vc/pkg/model"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/redis/go-redis/v9"
)

// Service holds the kv object
type Service struct {
	redisClient *redis.Client
	cfg         *model.Cfg
	log         *logger.Log
	probeStore  *apiv1_status.StatusProbeStore

	Doc *Doc
}

// New creates a new instance of kv
func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	c := &Service{
		cfg:        cfg,
		log:        log,
		probeStore: &apiv1_status.StatusProbeStore{},
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
func (c *Service) Status(ctx context.Context) *apiv1_status.StatusProbe {
	if time.Now().Before(c.probeStore.NextCheck.AsTime()) {
		return c.probeStore.PreviousResult
	}
	probe := &apiv1_status.StatusProbe{
		Name:          "kv",
		Healthy:       true,
		Message:       "OK",
		LastCheckedTS: timestamppb.Now(),
	}

	_, err := c.redisClient.Ping(ctx).Result()
	if err != nil {
		probe.Message = err.Error()
		probe.Healthy = false
	}
	c.probeStore.PreviousResult = probe
	c.probeStore.NextCheck = timestamppb.New(time.Now().Add(time.Second * 10))

	return probe
}

// Close closes the connection to the database
func (c *Service) Close(ctx context.Context) error {
	return c.redisClient.Close()
}
