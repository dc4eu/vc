package ca

import (
	"context"
	"vc/internal/issuer/db"
	"vc/internal/issuer/kv"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/go-logr/logr"
	"github.com/masv3971/gosunetca"
)

// Client is the client object for CA
type Client struct {
	caClient *gosunetca.Client
	db       *db.Service
	kv       *kv.Service
	log      *logger.Log
	cfg      *model.Cfg
}

// New creates a new client
func New(ctx context.Context, kvService *kv.Service, dbService *db.Service, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		db:  dbService,
		kv:  kvService,
		cfg: cfg,
		log: log,
	}

	ctx = logr.NewContext(ctx, log.Logger.WithName("gosunetca"))

	var err error
	c.caClient, err = gosunetca.New(ctx, gosunetca.Config{
		ServerURL: cfg.Issuer.CA.Addr,
		Token:     cfg.Issuer.CA.Token,
		Location:  cfg.Issuer.CA.Location,
		Reason:    cfg.Issuer.CA.Reason,
		UserAgent: "vc",
	})
	if err != nil {
		return nil, err
	}

	return c, nil
}
