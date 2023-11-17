package apiv1

import (
	"context"
	"vc/internal/issuer/ca"
	"vc/internal/issuer/db"
	"vc/internal/issuer/kv"
	"vc/internal/issuer/pda1"
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
	pda1      *pda1.Service
	rpcClient *rpcclient.Client
	ca        *ca.Client
	cfg       *model.Cfg
	db        *db.Service
	kv        *kv.Service
	log       *logger.Log
	tp        *trace.Tracer
}

// New creates a new instance of the public api
func New(ctx context.Context, rpcClient *rpcclient.Client, pda1 *pda1.Service, ca *ca.Client, kvService *kv.Service, db *db.Service, cfg *model.Cfg, tracer *trace.Tracer, logger *logger.Log) (*Client, error) {
	c := &Client{
		pda1:      pda1,
		cfg:       cfg,
		db:        db,
		kv:        kvService,
		log:       logger,
		ca:        ca,
		rpcClient: rpcClient,
		tp:        tracer,
	}

	c.log.Info("Started")

	return c, nil
}
