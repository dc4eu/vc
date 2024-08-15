package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/IBM/sarama"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

//TODO: gör generisk KafkaClient som konfigureras samt där man vid instansiering anger vilken ~"sender" som ska användas

type KafkaClient struct {
	producer sarama.SyncProducer
	config   *model.Cfg
	tracer   *trace.Tracer
	log      *logger.Log
	//TODO: deklarera och använd en generisk sender
}

// TODO: ta in en logger, mm och sätt i structen
func NewKafkaClient(ctx context.Context, config *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*KafkaClient, error) {
	log.Info("Kafka client starting ...")

	//TODO: saramaConfig from file inkl brokers
	saramaConfig := sarama.NewConfig()
	saramaConfig.Producer.Return.Successes = true
	saramaConfig.Producer.RequiredAcks = sarama.WaitForAll
	saramaConfig.Producer.Idempotent = true // Only-once delivery
	saramaConfig.Net.MaxOpenRequests = 1
	saramaConfig.Producer.Retry.Max = 3
	saramaConfig.Net.SASL.Enable = false //TODO: Activate SASL-auth when needed
	//TODO add other sec configs here

	if err := saramaConfig.Validate(); err != nil {
		return nil, err
	}

	brokers := []string{"kafka0:9092", "kafka1:9092"}

	producer, err := sarama.NewSyncProducer(brokers, saramaConfig)
	if err != nil {
		return nil, err
	}

	service := &KafkaClient{
		producer: producer,
		config:   config,
		tracer:   tracer,
		log:      log,
	}
	log.Info("Kafka client started")
	return service, nil
}

// Closing kafka client's resources
func (c *KafkaClient) Close(ctx context.Context) error {
	if err := c.producer.Close(); err != nil {
		return err
	}
	return nil
}

// TODO: ersätt med generisk sender
func (c *KafkaClient) SendMockNextMessage(payload *MockNextRequest) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	headers := []sarama.RecordHeader{
		{Key: []byte("my-header-key-1"), Value: []byte("my-header-value-1")},
	}

	message := &sarama.ProducerMessage{
		Topic: "topic_mock_next",
		Key:   sarama.StringEncoder(payload.AuthenticSourcePersonId),
		Value: sarama.ByteEncoder(jsonData),
		//TODO: remove headers, just a test of headers in a message
		Headers: headers,
		//TODO: remove metadata, just a test of metadata in a message
		Metadata: "metadata1 that only exist in the message before sending to broker",
	}
	partition, offset, err := c.producer.SendMessage(message)
	if err != nil {
		return err
	} else {
		//TODO: fixa loggning nedan samt på fler ställen rörande kafka
		c.log.Debug(fmt.Sprintf("Kafka message with key %s sent to partition %d at offset %d to topic %s\n", payload.AuthenticSourcePersonId, partition, offset, message.Topic))
	}

	return nil
}
