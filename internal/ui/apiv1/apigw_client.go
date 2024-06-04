package apiv1

import (
	apigw_apiv1 "vc/internal/apigw/apiv1"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

type APIGWClient struct {
	*VCBaseClient
}

func NewAPIGWClient(cfg *model.Cfg, tracer *trace.Tracer, logger *logger.Log) *APIGWClient {
	return &APIGWClient{
		VCBaseClient: NewClient("APIGW", cfg.UI.Services.APIGW.BaseURL, tracer, logger),
	}
}

func (c *APIGWClient) Portal(req *PortalRequest) (any, error) {
	reply, err := c.DoPostJSON("/api/v1/portal", req)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (c *APIGWClient) Status() (any, error) {
	reply, err := c.DoGetJSON("/health")
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (c *APIGWClient) Upload(req *apigw_apiv1.UploadRequest) (any, error) {
	reply, err := c.DoPostJSON("/api/v1/upload", req)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
