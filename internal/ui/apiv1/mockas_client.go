package apiv1

import (
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

type MockASClient struct {
	*VCBaseClient
}

func NewMockASClient(cfg *model.Cfg, tracer *trace.Tracer, logger *logger.Log) *MockASClient {
	return &MockASClient{
		VCBaseClient: NewClient("APIGW", cfg.UI.Services.MockAS.BaseURL, tracer, logger),
	}
}

func (mockasc *MockASClient) MockNext(req *MockNextRequest) (any, error) {
	reply, err := mockasc.DoPostJSON("/api/v1/mock/next", req)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
