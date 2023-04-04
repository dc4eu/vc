package ca

import (
	"context"
	"wallet/pkg/logger"
	"wallet/pkg/model"

	"github.com/masv3971/gosunetca"
)

// Client is the client object for ca
type Client struct {
	caClient *gosunetca.Client
	log      *logger.Logger
	cfg      *model.Cfg
}

// New creates a new client
func New(ctx context.Context, cfg *model.Cfg, log *logger.Logger) (*Client, error) {
	c := &Client{
		cfg: cfg,
		log: log,
	}

	var err error
	c.caClient, err = gosunetca.New(gosunetca.Config{
		ServerURL: cfg.Issuer.CA.ServerURL,
		Token:     cfg.Issuer.CA.Token,
		UserAgent: "wallet",
	})
	if err != nil {
		return nil, err
	}

	return c, nil
}
