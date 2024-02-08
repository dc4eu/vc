package apiv1

import (
	"context"
	"vc/internal/issuer/db"
	"vc/internal/issuer/pda1"
	"vc/internal/issuer/simplequeue"
	"vc/pkg/kvclient"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/rpcclient"
	"vc/pkg/trace"
)

//	@title		Issuer API
//	@version	0.1.0
//	@BasePath	/issuer/api/v1

// Client holds the public api object
type Client struct {
	simpleQueue *simplequeue.Service
	pda1        *pda1.Service
	rpcClient   *rpcclient.Client
	cfg         *model.Cfg
	db          *db.Service
	kv          *kvclient.Client
	log         *logger.Log
	tp          *trace.Tracer
}

// New creates a new instance of the public api
func New(ctx context.Context, simpleQueueService *simplequeue.Service, rpcClient *rpcclient.Client, pda1 *pda1.Service, kv *kvclient.Client, db *db.Service, cfg *model.Cfg, tracer *trace.Tracer, logger *logger.Log) (*Client, error) {
	c := &Client{
		simpleQueue: simpleQueueService,
		pda1:        pda1,
		cfg:         cfg,
		db:          db,
		kv:          kv,
		log:         logger,
		rpcClient:   rpcClient,
		tp:          tracer,
	}

	c.log.Info("Started")

	return c, nil
}
