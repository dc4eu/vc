package apiv1

import (
	"context"
	"vc/internal/apigw/db"
	"vc/internal/apigw/simplequeue"
	"vc/pkg/datastoreclient"
	"vc/pkg/kvclient"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

//	@title		Datastore API
//	@version	2.8
//	@BasePath	/api/v1

// Client holds the public api object
type Client struct {
	cfg             *model.Cfg
	db              *db.Service
	log             *logger.Log
	tp              *trace.Tracer
	kv              *kvclient.Client
	simpleQueue     *simplequeue.Service
	datastoreClient *datastoreclient.Client
}

// New creates a new instance of the public api
func New(ctx context.Context, kv *kvclient.Client, db *db.Service, simplequeue *simplequeue.Service, tp *trace.Tracer, cfg *model.Cfg, logger *logger.Log) (*Client, error) {
	c := &Client{
		cfg:         cfg,
		db:          db,
		log:         logger,
		kv:          kv,
		tp:          tp,
		simpleQueue: simplequeue,
	}

	// Specifies the issuer configuration based on the issuer identifier, should be initialized in main I guess.
	issuerIdentifier := cfg.Issuer.Identifier
	issuerCFG := cfg.AuthenticSources[issuerIdentifier]

	var err error
	c.datastoreClient, err = datastoreclient.New(&datastoreclient.Config{
		URL: issuerCFG.AuthenticSourceEndpoint.URL,
	})
	if err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}
