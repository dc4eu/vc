package apiv1

import (
	"context"
	"vc/pkg/kafka"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

// Client holds the public api object
type Client struct {
	cfg                  *model.Cfg
	tp                   *trace.Tracer
	log                  *logger.Log
	apigwClient          *APIGWClient
	mockasClient         *MockASClient
	kafkaMessageProducer *KafkaMessageProducer
}

func New(ctx context.Context, cfg *model.Cfg, tp *trace.Tracer, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:          cfg,
		tp:           tp,
		log:          log,
		apigwClient:  NewAPIGWClient(cfg, tp, log.New("apiwg_client")),
		mockasClient: NewMockASClient(cfg, tp, log.New("mockas_client")),
	}

	if cfg.Common.Kafka.Enabled {
		kafkaMessageProducer, err := NewKafkaMessageProducer(kafka.CommonProducerConfig(), ctx, cfg, tp, log)
		if err != nil {
			return nil, err
		}
		c.kafkaMessageProducer = kafkaMessageProducer
	} else {
		log.Info("Kafka disabled - no Kafka message producer client created")
	}

	c.log.Info("Started")

	return c, nil
}

func (c *Client) Close(ctx context.Context) error {
	if c.kafkaMessageProducer != nil {
		return c.kafkaMessageProducer.Close(ctx)
	}
	return nil
}
