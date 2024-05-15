package vcclient

import (
	"vc/internal/ui/representations"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

type APIGWClient struct {
	*VCBaseClient
}

func NewAPIGWClient(cfg *model.Cfg, tracer *trace.Tracer, logger *logger.Log) *APIGWClient {
	return &APIGWClient{
		VCBaseClient: New("APIGW", cfg.UI.Services.APIGW.BaseURL, tracer, logger),
	}
}

func (apigwc *APIGWClient) Portal(req *representations.PortalRequest) (any, error) {
	reply, err := apigwc.DoPostJSON("/api/v1/portal", req)
	if err != nil {
		return nil, err
	}
	//TODO impl Portal
	return reply, nil
}
