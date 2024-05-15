package vcclient

import (
	rep "vc/internal/ui/representations"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

type MockASClient struct {
	*VCBaseClient
}

func NewMockASClient(cfg *model.Cfg, tracer *trace.Tracer, logger *logger.Log) *MockASClient {
	return &MockASClient{
		VCBaseClient: New("APIGW", cfg.UI.Services.MockAS.BaseURL, tracer, logger),
	}
}

func (mockasc *MockASClient) MockNext(req *rep.PortalRequest) (any, error) {
	reply, err := mockasc.DoPostJSON("/api/v1/mock/next", req)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
