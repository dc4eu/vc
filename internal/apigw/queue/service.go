package queue

import (
	"context"
	"errors"
	"time"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/protocol"
	"go.opentelemetry.io/otel/codes"
)

// Service is the queue service
type Service struct {
	cfg         *model.Cfg
	log         *logger.Log
	tp          *trace.Tracer
	kafkaWriter *kafka.Writer
	kafkaReader *kafka.Reader
	kafkaClient *kafka.Client
	kafkaConn   *kafka.Conn
}

// New creates a new queue service
func New(ctx context.Context, cfg *model.Cfg, trace *trace.Tracer, log *logger.Log) (*Service, error) {
	service := &Service{
		cfg: cfg,
		log: log,
		tp:  trace,
	}

	service.newKafkaClient(ctx)

	return service, nil
}

func (s *Service) newKafkaClient(ctx context.Context) {
	ctx, span := s.tp.Start(ctx, "queue:newKafkaClient")
	defer span.End()

	s.kafkaClient = &kafka.Client{
		Addr:      kafka.TCP(s.cfg.Common.Queues.Kafka.Brokers...),
		Timeout:   10 * time.Second,
		Transport: nil,
	}
}

func (s *Service) newReader(ctx context.Context, topic, groupID string) *kafka.Reader {
	ctx, span := s.tp.Start(ctx, "queue:newReader")
	defer span.End()

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  []string{"vc_kafka_1:9092"},
		GroupID:  groupID,
		Topic:    topic,
		MinBytes: 10,
		MaxBytes: 10e6,
		MaxWait:  1 * time.Second,
	})

	return reader
}

// Enqueue writes one message to the queue
func (s *Service) Enqueue(ctx context.Context, topic, key string, msg []byte, headers []protocol.Header) error {
	ctx, span := s.tp.Start(ctx, "queue:Enqueue")
	defer span.End()

	if topic == "" {
		return errors.New("topic is required")
	}
	if msg == nil {
		return errors.New("message is required")
	}
	if key == "" {
		return errors.New("key is required")
	}

	uuid := uuid.NewString()

	s.log.Info("Writing message to queue", "topic", topic, "key", key, "message", msg, "uuid", uuid)

	_, err := s.kafkaClient.CreateTopics(ctx, &kafka.CreateTopicsRequest{
		Topics: []kafka.TopicConfig{
			{
				Topic:             topic,
				NumPartitions:     0,
				ReplicationFactor: 0,
			},
		},
	})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	r := kafka.NewRecordReader(kafka.Record{
		Offset:  0,
		Time:    time.Time{},
		Key:     protocol.NewBytes([]byte(key)),
		Value:   protocol.NewBytes(msg),
		Headers: headers,
	})

	_, err = s.kafkaClient.Produce(ctx, &kafka.ProduceRequest{
		Topic:           topic,
		Partition:       0,
		RequiredAcks:    0,
		MessageVersion:  0,
		TransactionalID: uuid,
		Records:         r,
		Compression:     0,
	})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// Close closes the service
func (s *Service) Close(ctx context.Context) error {
	return nil
}
