package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IBM/sarama"
	"reflect"
	"vc/internal/ui/apiv1"
	"vc/pkg/logger"
	"vc/pkg/messagebroker/kafka"
	"vc/pkg/model"
	"vc/pkg/trace"
)

type KafkaMessageProducer struct {
	kafkaMessageProducerClient *kafka.MessageSyncProducerClient
}

func NewEventPublisher(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (apiv1.EventPublisher, error) {
	kafkaMessageProducerClient, err := kafka.NewMessageSyncProducerClient(kafka.CommonProducerConfig(cfg), ctx, cfg, tracer, log.New("kafka_message_producer_client"))
	if err != nil {
		return nil, err
	}
	return &KafkaMessageProducer{
		kafkaMessageProducerClient: kafkaMessageProducerClient,
	}, nil
}

func (s *KafkaMessageProducer) MockNext(mockNextRequest *apiv1.MockNextRequest) error {
	if mockNextRequest == nil {
		return errors.New("param mockNextRequest is nil")
	}

	jsonMarshaled, err := json.Marshal(mockNextRequest)
	if err != nil {
		return err
	}

	//TODO(mk): make header code below generic and move to kafka client
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
