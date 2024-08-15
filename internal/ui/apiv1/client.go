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

func New(ctx context.Context, cfg *model.Cfg, tp *trace.Tracer, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:          cfg,
		tp:           tp,
		log:          log,
		apigwClient:  NewAPIGWClient(cfg, tp, log.New("ui-apiwg-client")),
		mockasClient: NewMockASClient(cfg, tp, log.New("ui-mockas-client")),
	}

	if cfg.Common.Kafka.Enabled {
		kafkaClient, err := NewKafkaClient(ctx, cfg, tp, log.New("ui-kafka-client"))
		if err != nil {
			return nil, err
		}
		c.kafkaClient = kafkaClient
	} else {
		log.Info("Kafka disabled - no Kafka client created")
	}

	c.log.Info("Started")

	return c, nil
}

func (c *Client) Close(ctx context.Context) error {
	if c.kafkaClient != nil {
		return c.kafkaClient.Close(ctx)
	}
	return nil
}
