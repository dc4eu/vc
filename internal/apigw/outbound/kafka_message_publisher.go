package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IBM/sarama"
	"reflect"
	"vc/internal/apigw/apiv1"
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

func (s *KafkaMessageProducer) Upload(uploadRequest *apiv1.UploadRequest) error {
	if uploadRequest == nil {
		return errors.New("param uploadRequest is nil")
	}

	jsonMarshaled, err := json.Marshal(uploadRequest)
	if err != nil {
		return err
	}

	//TODO(mk): make header code below including in other kafka publisher generic and move to kafka client
	paramType := reflect.TypeOf(uploadRequest).Elem().Name()
	typeHeader := []byte(paramType)
	headers := []sarama.RecordHeader{
		{Key: []byte(kafka.TypeOfStructInMessageValue), Value: typeHeader},
	}

	return s.kafkaMessageProducerClient.PublishMessage(kafka.TopicUpload, uploadRequest.Meta.DocumentID, jsonMarshaled, headers)
}

func (s *KafkaMessageProducer) Close(ctx context.Context) error {
	if s.kafkaMessageProducerClient != nil {
		return s.kafkaMessageProducerClient.Close(ctx)
	}
	return nil
}
