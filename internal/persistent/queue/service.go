package queue

import (
	"context"
	"errors"
	"time"
	"vc/internal/persistent/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/topicnames"
	"vc/pkg/trace"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/protocol"
)

type ConsumerService interface {
	close(ctx context.Context) error
	worker(ctx context.Context) error
}

// Service is the queue service
type Service struct {
	cfg         *model.Cfg
	log         *logger.Log
	db          *db.Service
	tp          *trace.Tracer
	kafkaWriter *kafka.Writer
	kafkaReader *kafka.Reader
	kafkaClient *kafka.Client
	kafkaConn   *kafka.Conn

	ConsumerServices map[string]ConsumerService

	QueueingVCSaveUploadV0Service *QueueingVCSaveDocumentV0
}

// New creates a new queue service
func New(ctx context.Context, cfg *model.Cfg, db *db.Service, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	service := &Service{
		cfg:              cfg,
		log:              log,
		tp:               tracer,
		db:               db,
		ConsumerServices: make(map[string]ConsumerService),
	}

	service.newKafkaClient(ctx)

	newQueueingVCSaveUploadV0(ctx, service, topicnames.QueuingVCSaveDocumentV0, "test_group_id", log.New(topicnames.QueuingVCSaveDocumentV0))
	newQueueingVCDeleteUploadV0(ctx, service, topicnames.QueuingVCDeleteDocumentV0, "test_group_id", log.New(topicnames.QueuingVCDeleteDocumentV0))

	service.log.Info("Started")

	return service, nil
}

func (s *Service) newKafkaClient(ctx context.Context) {
	ctx, span := s.tp.Start(ctx, "queue:NewKafkaClient")
	defer span.End()

	s.kafkaClient = &kafka.Client{
		Addr:      kafka.TCP(s.cfg.Common.Queues.Kafka.Brokers...),
		Timeout:   10 * time.Second,
		Transport: nil,
	}
}

func (s *Service) newConsumer(ctx context.Context, topic, groupID string) *kafka.Reader {
	ctx, span := s.tp.Start(ctx, "queue:newConsumer")
	defer span.End()

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  s.cfg.Common.Queues.Kafka.Brokers,
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

	//s.log.Info("Writing message to queue", "topic", topic, "key", key, "message", msg, "uuid", uuid)

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
		s.log.Error(err, "failed to create topic")
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
		s.log.Error(err, "1.failed to write message to kafka")
		return err
	}

	return nil
}

// Close closes the service
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Quit")

	ctx.Done()

	return nil
}
