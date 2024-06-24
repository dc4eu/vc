package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/IBM/sarama"
)

type KafkaClient struct {
	producer sarama.SyncProducer
}

// TODO: ta in en logger och sätt i structen
func NewKafkaClient() (*KafkaClient, error) {
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Idempotent = true // Only-once delivery
	config.Net.MaxOpenRequests = 1
	config.Producer.Retry.Max = 3
	config.Net.SASL.Enable = false //TODO: Activate SASL-auth when needed
	//TODO add other sec configs here

	producer, err := sarama.NewSyncProducer([]string{"kafka:9092"}, config)
	if err != nil {
		return nil, err
	}

	service := &KafkaClient{
		producer: producer,
	}
	return service, nil
}

// Shutdown closing kafka client's resources
func (c *KafkaClient) Shutdown(ctx context.Context) error {
	if err := c.producer.Close(); err != nil {
		return err
	}
	return nil
}

func (c *KafkaClient) SendMockNextMessage(payload *MockNextRequest) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	message := &sarama.ProducerMessage{
		Topic: "topic_mock_next",
		Key:   sarama.StringEncoder(payload.AuthenticSourcePersonId),
		Value: sarama.ByteEncoder(jsonData),
	}
	partition, offset, err := c.producer.SendMessage(message)
	if err != nil {
		return err
	} else {
		//TODO: fixa loggning nedan samt på fler ställen rörande kafka
		fmt.Printf("Kafka message with key %s sent to partition %d at offset %d to topic %s\n", payload.AuthenticSourcePersonId, partition, offset, message.Topic)
	}

	return nil
}
