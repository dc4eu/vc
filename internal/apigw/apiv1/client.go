package apiv1

import (
	"context"
	"vc/internal/apigw/db"
	"vc/pkg/datastoreclient"
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

	// Specifies the issuer configuration based on the issuer identifier, should be initialized in main I guess.
	issuerIdentifier := cfg.Issuer.Identifier
	issuerCFG := cfg.AuthenticSources[issuerIdentifier]

	var err error
	c.datastoreClient, err = datastoreclient.New(&datastoreclient.Config{URL: issuerCFG.AuthenticSourceEndpoint.URL})
	if err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}
