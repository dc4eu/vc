package apiv1

import (
	"context"
	"net/http"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/brianvoe/gofakeit/v6"
)

//	@title		Issuer API
//	@version	0.1.0
//	@BasePath	/issuer/api/v1

// Client holds the public api object
type Client struct {
	cfg        *model.Cfg
	log        *logger.Log
	tp         *trace.Tracer
	httpClient *http.Client

	PDA1 *PDA1Service
	EHIC *EHICService
}

// New creates a new instance of the public api
func New(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, logger *logger.Log) (*Client, error) {
	c := &Client{
		cfg:        cfg,
		log:        logger,
		tp:         tracer,
		httpClient: &http.Client{},

		PDA1: &PDA1Service{},
		EHIC: &EHICService{},
	}

	c.PDA1 = &PDA1Service{
		Client: c,
	}
	c.EHIC = &EHICService{
		Client: c,
	}

	c.log.Info("Started")

	return c, nil
}

func (c *Client) randomISO31661Alpha3EU() string {
	return gofakeit.RandomString([]string{
		"AUT", "BEL", "BGR", "HRV", "CYP",
		"CZE", "DNK", "EST", "FIN", "FRA",
		"DEU", "GRC", "HUN", "IRL", "ITA",
		"LVA", "LTU", "LUX", "MLT", "NLD",
		"POL", "PRT", "ROU", "SVK", "SVN",
		"ESP", "SWE",
	})
}

func (c *Client) randomISO31661Alpha2EU() string {
	return gofakeit.RandomString([]string{
		"AT", "BE", "BG", "HR", "CY",
		"CZ", "DK", "EE", "FI", "FR",
		"DE", "GR", "HU", "IE", "IT",
		"LV", "LT", "LU", "MT", "NL",
		"PL", "PT", "RO", "SK", "SI",
		"ES", "SE",
	})
}
