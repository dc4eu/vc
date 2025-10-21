package apiv1

import (
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

type VerifierClient struct {
	*VCBaseClient
}

func NewVerifierClient(cfg *model.Cfg, tracer *trace.Tracer, logger *logger.Log) *VerifierClient {
	return &VerifierClient{
		VCBaseClient: NewClient("Verifier", cfg.UI.Services.Verifier.BaseURL, tracer, logger),
	}
}

func (c *VerifierClient) Health() (any, error) {
	reply, err := c.DoGetJSON("/health")
	if err != nil {
		return nil, err
	}
	return reply, nil
}
