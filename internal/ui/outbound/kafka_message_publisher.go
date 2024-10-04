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

type kafkaMessageProducer struct {
	client *kafka.SyncProducerClient
}

func New(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (apiv1.EventPublisher, error) {
	client, err := kafka.NewSyncProducerClient(ctx, kafka.CommonProducerConfig(cfg), cfg, tracer, log.New("kafka_message_producer_client"))
	if err != nil {
		return nil, err
	}
	return &kafkaMessageProducer{
		client: client,
	}, nil
}

func (s *kafkaMessageProducer) MockNext(mockNextRequest *apiv1.MockNextRequest) error {
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

	return s.client.PublishMessage(kafka.TopicMockNext, mockNextRequest.AuthenticSourcePersonId, jsonMarshaled, headers)
}

func (s *kafkaMessageProducer) Close(ctx context.Context) error {
	if s.client != nil {
		return s.client.Close(ctx)
	}
	return nil
}
