package ca

import (
	"context"
	"vc/internal/issuer/db"
	"vc/internal/issuer/kv"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/masv3971/gosunetca"
)

// Client is the client object for CA
type Client struct {
	caClient *gosunetca.Client
	db       *db.Service
	kv       *kv.Service
	log      *logger.Logger
	cfg      *model.Cfg
}

// New creates a new client
func New(ctx context.Context, kvService *kv.Service, dbService *db.Service, cfg *model.Cfg, log *logger.Logger) (*Client, error) {
	c := &Client{
		db:  dbService,
		kv:  kvService,
		cfg: cfg,
		log: log,
	}

	var err error
	c.caClient, err = gosunetca.New(gosunetca.Config{
		ServerURL: cfg.Issuer.CA.Addr,
		Token:     cfg.Issuer.CA.Token,
		UserAgent: "vc",
	})
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Client) sign(in, out string) error {
	return nil
}
