package kafka

import (
	"context"
	"fmt"
	"github.com/IBM/sarama"
	"log"
	"sync"
	"time"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

const (
	TopicMockNextName          = "topic_mock_next"
	TopicUpload                = "topic_upload"
	TypeOfStructInMessageValue = "type_of_struct_in_value"
)

type KafkaMessageSyncProducerClient struct {
	producer sarama.SyncProducer
	config   *model.Cfg
	tracer   *trace.Tracer
	log      *logger.Log
}

func NewKafkaMessageSyncProducerClient(ctx context.Context, config *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*KafkaMessageSyncProducerClient, error) {
	log.Info("Starting ...")

	saramaConfig := sarama.NewConfig()
	saramaConfig.Producer.Return.Successes = true
	saramaConfig.Producer.RequiredAcks = sarama.WaitForAll
	saramaConfig.Producer.Idempotent = true
	saramaConfig.Net.MaxOpenRequests = 1
	saramaConfig.Producer.Retry.Max = 3
	saramaConfig.Net.SASL.Enable = false

	if err := saramaConfig.Validate(); err != nil {
		return nil, err
	}

	producer, err := sarama.NewSyncProducer(config.Common.Kafka.Brokers, saramaConfig)
	if err != nil {
		return nil, err
	}

	client := &KafkaMessageSyncProducerClient{
		producer: producer,
		config:   config,
		tracer:   tracer,
		log:      log,
	}

	log.Info("... started.")
	return client, nil
}

func (c *KafkaMessageSyncProducerClient) Close(ctx context.Context) error {
	err := c.producer.Close()
	if err != nil {
		c.log.Error(err, "Error closing")
		return err
	}
	c.log.Info("Closed")
	return nil
}

func (c *KafkaMessageSyncProducerClient) PublishMessage(topic string, key string, json []byte, headers []sarama.RecordHeader) error {
	message := &sarama.ProducerMessage{
		Topic:   topic,
		Key:     sarama.StringEncoder(key),
		Value:   sarama.ByteEncoder(json),
		Headers: headers,
	}

	partition, offset, err := c.producer.SendMessage(message)
	if err != nil {
		return err
	} else {
		c.log.Debug(fmt.Sprintf("Kafka message with key %s sent to partition %d at offset %d to topic %s\n", key, partition, offset, topic))
	}

	return nil
}

type KafkaMessageConsumerClient struct {
	//TODO: impl
}

type KafkaTopicConfig struct {
	Topic         string
	ConsumerGroup string
}

type Consumer interface {
	Start(handlerFactory func(string) sarama.ConsumerGroupHandler) error
	Close(ctx context.Context) error
}

type BaseKafkaConsumer struct {
	saramaConfig *sarama.Config
	topicConfigs []KafkaTopicConfig
	brokers      []string
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
}

func NewBaseKafkaConsumer(brokers []string, topicConfigs []KafkaTopicConfig, config *sarama.Config) (*BaseKafkaConsumer, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &BaseKafkaConsumer{
		brokers:      brokers,
		topicConfigs: topicConfigs,
		ctx:          ctx,
		cancel:       cancel,
		wg:           sync.WaitGroup{},
	}, nil
}

func (bc *BaseKafkaConsumer) Start(handlerFactory func(string) sarama.ConsumerGroupHandler) error {
	for _, topicConfig := range bc.topicConfigs {
		consumerGroup, err := sarama.NewConsumerGroup(bc.brokers, topicConfig.ConsumerGroup, bc.saramaConfig)
		if err != nil {
			return err
		}

		bc.wg.Add(1)
		go func(group sarama.ConsumerGroup, topic string) {
			defer bc.wg.Done()
			for {
				handler := handlerFactory(topic)
				if err := group.Consume(bc.ctx, []string{topic}, handler); err != nil {
					//TODO: Hantera fel och potentiell återkoppling
					time.Sleep(1 * time.Second) //TODO: justera backoff till mer avancerad
				}

				if bc.ctx.Err() != nil {
					return
				}
			}
		}(consumerGroup, topicConfig.Topic)
	}
	return nil
}

func (bc *BaseKafkaConsumer) Close(ctx context.Context) error {
	bc.cancel()
	bc.wg.Wait()
	return nil
}

type MessageHandler interface {
	HandleMessage(ctx context.Context, message *sarama.ConsumerMessage) error
}

type ConsumerGroupHandler struct {
	Handlers map[string]MessageHandler
}

func (cgh *ConsumerGroupHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (cgh *ConsumerGroupHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }

func (cgh *ConsumerGroupHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	handler, exists := cgh.Handlers[claim.Topic()]
	if !exists {
		log.Printf("No handler for topic: %s", claim.Topic())
		return nil
	}
	for message := range claim.Messages() {
		if err := handler.HandleMessage(session.Context(), message); err != nil {
			//TODO: Hantera fel, potentiellt skicka till error-topic
			log.Printf("Error handling message from topic %s: %v", claim.Topic(), err)
		}
		session.MarkMessage(message, "")
	}
	return nil
}
