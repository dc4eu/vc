package apiv1

import (
	"context"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
	"vc/pkg/vcclient"
)

// Client holds the public api object
type Client struct {
	cfg            *model.Cfg
	tracer         *trace.Tracer
	log            *logger.Log
	apigwClient    *APIGWClient
	mockasClient   *MockASClient
	verifierClient *VerifierClient
	eventPublisher EventPublisher

	vcClient *vcclient.Client
}

// New creates a new instance of user interface web page
func New(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, eventPublisher EventPublisher, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:            cfg,
		tracer:         tracer,
		log:            log.New("apiv1"),
		apigwClient:    NewAPIGWClient(cfg, tracer, log.New("apiwg_client")),
		mockasClient:   NewMockASClient(cfg, tracer, log.New("mockas_client")),
		verifierClient: NewVerifierClient(cfg, tracer, log.New("verifier_client")),
		eventPublisher: eventPublisher,
	}

	vcClientConfig := &vcclient.Config{
		ApigwFQDN: cfg.UI.Services.APIGW.BaseURL,
	}

	var err error
	c.vcClient, err = vcclient.New(vcClientConfig, c.log)
	if err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}
