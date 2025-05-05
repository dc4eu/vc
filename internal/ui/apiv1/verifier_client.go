package apiv1

import (
	apiv1_verifier "vc/internal/verifier/apiv1"
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

func (c *VerifierClient) GetVPFlowDebugInfo(req *apiv1_verifier.VPFlowDebugInfoRequest) (any, error) {
	reply, err := c.DoPostJSON("/debug/vp-flow", req)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
