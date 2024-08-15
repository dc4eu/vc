package apiv1

import (
	"context"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

// Client holds the public api object
type Client struct {
	cfg          *model.Cfg
	tp           *trace.Tracer
	log          *logger.Log
	apigwClient  *APIGWClient
	mockasClient *MockASClient
	kafkaClient  *KafkaClient
}

func New(ctx context.Context, cfg *model.Cfg, tp *trace.Tracer, kafkaClient *KafkaClient, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:          cfg,
		tp:           tp,
		log:          log,
		apigwClient:  NewAPIGWClient(cfg, tp, log.New("ui_apiwg_client")),
		mockasClient: NewMockASClient(cfg, tp, log.New("ui_mockas_client")),
		kafkaClient:  kafkaClient,
	}

	//if kafkaClient, err := NewKafkaClient(); err != nil {
	//	return nil, err
	//} else {
	//	c.kafkaClient = kafkaClient
	//}

	c.log.Info("Started")

	return c, nil
}

//func (c *Client) Shutdown(ctx context.Context) error {
//	if c.kafkaClient != nil {
//		return c.kafkaClient.Shutdown(ctx)
//	}
//	return nil
//}
