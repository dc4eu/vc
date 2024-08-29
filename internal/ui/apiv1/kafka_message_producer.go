package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IBM/sarama"
	"reflect"
	"vc/pkg/kafka"
)

type KafkaMessageProducer struct {
	kafkaMessageProducerClient *kafka.KafkaMessageSyncProducerClient
}

func NewKafkaMessageProducer(kafkaMessageProducerClient *kafka.KafkaMessageSyncProducerClient) *KafkaMessageProducer {
	return &KafkaMessageProducer{
		kafkaMessageProducerClient: kafkaMessageProducerClient,
	}
}

func (s *KafkaMessageProducer) MockNext(mockNextRequest *MockNextRequest) error {
	if mockNextRequest == nil {
		return errors.New("param mockNextRequest is nil")
	}

	jsonMarshaled, err := json.Marshal(mockNextRequest)
	if err != nil {
		return err
	}

	paramType := reflect.TypeOf(mockNextRequest).Elem().Name()
	typeHeader := []byte(paramType)

	headers := []sarama.RecordHeader{
		{Key: []byte(kafka.TypeOfStructInMessageValue), Value: typeHeader},
	}

	return s.kafkaMessageProducerClient.PublishMessage(kafka.TopicMockNextName, mockNextRequest.AuthenticSourcePersonId, jsonMarshaled, headers)
}

func (s *KafkaMessageProducer) Close(ctx context.Context) error {
	if s.kafkaMessageProducerClient != nil {
		return s.kafkaMessageProducerClient.Close(ctx)
	}
	return nil
}
