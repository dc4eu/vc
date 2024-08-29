package kafka

import (
	"context"
	"fmt"
	"github.com/IBM/sarama"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

const (
	TopicMockNextName          = "topic_mock_next"
	TopicUpload                = "topic_upload"
	TypeOfStructInMessageValue = "type_of_struct_in_value"
)

type KafkaMessageSyncProducerClient struct {
	producer sarama.SyncProducer
	config   *model.Cfg
	tracer   *trace.Tracer
	log      *logger.Log
}

func NewKafkaMessageSyncProducerClient(ctx context.Context, config *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*KafkaMessageSyncProducerClient, error) {
	log.Info("Starting ...")

	saramaConfig := sarama.NewConfig()
	saramaConfig.Producer.Return.Successes = true
	saramaConfig.Producer.RequiredAcks = sarama.WaitForAll
	saramaConfig.Producer.Idempotent = true
	saramaConfig.Net.MaxOpenRequests = 1
	saramaConfig.Producer.Retry.Max = 3
	saramaConfig.Net.SASL.Enable = false

	if err := saramaConfig.Validate(); err != nil {
		return nil, err
	}

	producer, err := sarama.NewSyncProducer(config.Common.Kafka.Brokers, saramaConfig)
	if err != nil {
		return nil, err
	}

	client := &KafkaMessageSyncProducerClient{
		producer: producer,
		config:   config,
		tracer:   tracer,
		log:      log,
	}

	log.Info("... started.")
	return client, nil
}

func (c *KafkaMessageSyncProducerClient) Close(ctx context.Context) error {
	err := c.producer.Close()
	if err != nil {
		c.log.Error(err, "Error closing")
		return err
	}
	c.log.Info("Closed")
	return nil
}

func (c *KafkaMessageSyncProducerClient) PublishMessage(topic string, key string, json []byte, headers []sarama.RecordHeader) error {
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

type KafkaMessageConsumerClient struct {
	//TODO: impl
}
