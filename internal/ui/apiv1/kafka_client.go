package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/IBM/sarama"
)

//TODO: gör generisk KafkaClient som konfigureras samt där man vid instansiering anger vilken ~"sender" som ska användas

type KafkaClient struct {
	producer sarama.SyncProducer
	//TODO: deklarera en generisk sender istället för att hålla
}

// TODO: ta in en logger, mm och sätt i structen
func NewKafkaClient() (*KafkaClient, error) {
	//TODO: config from file
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Idempotent = true // Only-once delivery
	config.Net.MaxOpenRequests = 1
	config.Producer.Retry.Max = 3
	config.Net.SASL.Enable = false //TODO: Activate SASL-auth when needed
	//TODO add other sec configs here

	err := config.Validate()
	if err != nil {
		return nil, err
	}

	brokers := []string{"kafka0:9092", "kafka1:9092"}
	producer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		return nil, err
	}

	service := &KafkaClient{
		producer: producer,
	}
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
		//TODO: remove headers, just a test of headers
		Headers: headers,
		//TODO: remove metadata, just a test of metadata
		Metadata: "metadata1 that only exist in the message before sending to broker",
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
