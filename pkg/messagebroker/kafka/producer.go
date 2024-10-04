package kafka

import (
	"context"
	"errors"
	"fmt"
	"github.com/IBM/sarama"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

// MessageConsumerClient ATTENTION: Start max one instance of consumer client for each service to keep resource usage low
type SyncProducerClient struct {
	producer sarama.SyncProducer
	cfg      *model.Cfg
	tracer   *trace.Tracer
	log      *logger.Log
}

func NewSyncProducerClient(ctx context.Context, saramaConfig *sarama.Config, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*SyncProducerClient, error) {
	client := &SyncProducerClient{
		cfg:    cfg,
		tracer: tracer,
		log:    log,
	}

	log.Info("Starting ...")

	if saramaConfig == nil {
		return nil, errors.New("param saramaConfig is nil")
	}
	if err := saramaConfig.Validate(); err != nil {
		return nil, err
	}

	var err error
	client.producer, err = sarama.NewSyncProducer(cfg.Common.Kafka.Brokers, saramaConfig)
	if err != nil {
		return nil, err
	}

	log.Info("... started.")
	return client, nil
}

func CommonProducerConfig(cfg *model.Cfg) *sarama.Config {
	//TODO(mk): set cfg from file - is now hardcoded
	//TODO(mk: enable security when publishing to Kafka
	saramaConfig := sarama.NewConfig()
	saramaConfig.Producer.Return.Successes = true
	saramaConfig.Producer.RequiredAcks = sarama.WaitForAll
	saramaConfig.Producer.Idempotent = true
	saramaConfig.Net.MaxOpenRequests = 1
	saramaConfig.Producer.Retry.Max = 3
	saramaConfig.Net.SASL.Enable = false
	// ...
	return saramaConfig
}

func (c *SyncProducerClient) Close(ctx context.Context) error {
	err := c.producer.Close()
	if err != nil {
		c.log.Error(err, "Error closing")
		return err
	}
	c.log.Info("Closed")
	return nil
}

func (c *SyncProducerClient) PublishMessage(topic string, key string, json []byte, headers []sarama.RecordHeader) error {
	//TODO(mk): create header data in this func, ie change func def.
	message := &sarama.ProducerMessage{
		Topic:   topic,
		Key:     sarama.StringEncoder(key),
		Value:   sarama.ByteEncoder(json),
		Headers: headers,
	}

	partition, offset, err := c.producer.SendMessage(message)
	if err != nil {
		return err
	} else {
		c.log.Debug(fmt.Sprintf("Kafka message with key %s sent to partition %d at offset %d to topic %s\n", key, partition, offset, topic))
	}

	return nil
}
