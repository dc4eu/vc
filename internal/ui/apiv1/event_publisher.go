package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IBM/sarama"
	"reflect"
	"vc/pkg/logger"
	"vc/pkg/messagebrokers/kafka"
	"vc/pkg/model"
	"vc/pkg/trace"
)

type EventPublisher interface {
	MockNext(mockNextRequest *MockNextRequest) error
	Close(ctx context.Context) error
}

type KafkaMessageProducer struct {
	kafkaMessageProducerClient *kafka.MessageSyncProducerClient
}

func NewKafkaMessageProducer(producerConfig *sarama.Config, ctx context.Context, config *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*KafkaMessageProducer, error) {
	kafkaMessageProducerClient, err := kafka.NewMessageSyncProducerClient(producerConfig, ctx, config, tracer, log.New("kafka_message_producer_client"))
	if err != nil {
		return nil, err
	}
	return &KafkaMessageProducer{
		kafkaMessageProducerClient: kafkaMessageProducerClient,
	}, nil
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

	return s.kafkaMessageProducerClient.PublishMessage(kafka.TopicMockNext, mockNextRequest.AuthenticSourcePersonId, jsonMarshaled, headers)
}

func (s *KafkaMessageProducer) Close(ctx context.Context) error {
	if s.kafkaMessageProducerClient != nil {
		return s.kafkaMessageProducerClient.Close(ctx)
	}
	return nil
}
