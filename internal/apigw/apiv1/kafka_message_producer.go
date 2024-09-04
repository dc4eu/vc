package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IBM/sarama"
	"reflect"
	"vc/pkg/kafka"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

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

func (s *KafkaMessageProducer) Upload(uploadRequest *UploadRequest) error {
	if uploadRequest == nil {
		return errors.New("param uploadRequest is nil")
	}

	jsonMarshaled, err := json.Marshal(uploadRequest)
	if err != nil {
		return err
	}

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
