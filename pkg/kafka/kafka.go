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
	TopicMockNext              = "topic_mock_next"
	TopicUpload                = "topic_upload"
	TypeOfStructInMessageValue = "type_of_struct_in_value"
)

type MessageSyncProducerClient struct {
	producer sarama.SyncProducer
	config   *model.Cfg
	tracer   *trace.Tracer
	log      *logger.Log
}

func NewMessageSyncProducerClient(producerConfig *sarama.Config, ctx context.Context, config *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*MessageSyncProducerClient, error) {
	log.Info("Starting ...")

	//TODO: validera så config ej är nil

	if err := producerConfig.Validate(); err != nil {
		return nil, err
	}

	producer, err := sarama.NewSyncProducer(config.Common.Kafka.Brokers, producerConfig)
	if err != nil {
		return nil, err
	}

	client := &MessageSyncProducerClient{
		producer: producer,
		config:   config,
		tracer:   tracer,
		log:      log,
	}

	log.Info("... started.")
	return client, nil
}

func CommonProducerConfig() *sarama.Config {
	producerConfig := sarama.NewConfig()
	producerConfig.Producer.Return.Successes = true
	producerConfig.Producer.RequiredAcks = sarama.WaitForAll
	producerConfig.Producer.Idempotent = true
	producerConfig.Net.MaxOpenRequests = 1
	producerConfig.Producer.Retry.Max = 3
	producerConfig.Net.SASL.Enable = false
	return producerConfig
}

func (c *MessageSyncProducerClient) Close(ctx context.Context) error {
	err := c.producer.Close()
	if err != nil {
		c.log.Error(err, "Error closing")
		return err
	}
	c.log.Info("Closed")
	return nil
}

func (c *MessageSyncProducerClient) PublishMessage(topic string, key string, json []byte, headers []sarama.RecordHeader) error {
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

type HandlerConfig struct {
	Topic         string
	ConsumerGroup string
}

type Consumer interface {
	Start(handlerFactory func(string) sarama.ConsumerGroupHandler) error
	Close(ctx context.Context) error
}

type MessageConsumerClient struct {
	consumerConfig *sarama.Config
	handlerConfigs []HandlerConfig
	brokers        []string
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	log            *logger.Log
}

func CommonConsumerConfig() *sarama.Config {
	consumerConfig := sarama.NewConfig()
	consumerConfig.Consumer.Offsets.Initial = sarama.OffsetOldest
	consumerConfig.Consumer.Group.Rebalance.GroupStrategies = []sarama.BalanceStrategy{sarama.NewBalanceStrategyRange()}
	consumerConfig.Net.SASL.Enable = false //TODO: Aktivera SASL-auth när det behövs
	return consumerConfig
}

func NewMessageConsumerClient(consumerConfig *sarama.Config, brokers []string, handlerConfigs []HandlerConfig, log *logger.Log) (*MessageConsumerClient, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &MessageConsumerClient{
		consumerConfig: consumerConfig,
		brokers:        brokers,
		handlerConfigs: handlerConfigs,
		ctx:            ctx,
		cancel:         cancel,
		wg:             sync.WaitGroup{},
		log:            log,
	}, nil
}

func (c *MessageConsumerClient) Start(handlerFactory func(string) sarama.ConsumerGroupHandler) error {
	for _, handlerConfig := range c.handlerConfigs {
		consumerGroup, err := sarama.NewConsumerGroup(c.brokers, handlerConfig.ConsumerGroup, c.consumerConfig)
		if err != nil {
			c.log.Error(err, "Error creating consumer group", "group", handlerConfig.ConsumerGroup)
			return err
		}
		c.log.Info("Started consumer group", "group", handlerConfig.ConsumerGroup)

		c.wg.Add(1)
		go func(group sarama.ConsumerGroup, topic string) {
			defer c.wg.Done()
			for {
				handler := handlerFactory(topic)
				if err := group.Consume(c.ctx, []string{topic}, handler); err != nil {
					//TODO: Hantera fel och potentiell återkoppling
					time.Sleep(1 * time.Second) //TODO: justera backoff till mer avancerad som tidigare
				}

				if c.ctx.Err() != nil {
					return
				}
			}
		}(consumerGroup, handlerConfig.Topic)
	}
	return nil
}

func (c *MessageConsumerClient) Close(ctx context.Context) error {
	c.cancel()
	c.wg.Wait()
	c.log.Info("Closed")
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
