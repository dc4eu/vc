package kafka

import (
	"context"
	"errors"
	"fmt"
	"github.com/IBM/sarama"
	"reflect"
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

// MessageConsumerClient ATTENTION: Start max one instance of consumer client for each service to keep resource usage low
type MessageSyncProducerClient struct {
	producer sarama.SyncProducer
	cfg      *model.Cfg
	tracer   *trace.Tracer
	log      *logger.Log
}

func NewMessageSyncProducerClient(producerConfig *sarama.Config, ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*MessageSyncProducerClient, error) {
	log.Info("Starting ...")

	if producerConfig == nil {
		return nil, errors.New("param producerConfig is nil")
	}
	if err := producerConfig.Validate(); err != nil {
		return nil, err
	}

	producer, err := sarama.NewSyncProducer(cfg.Common.Kafka.Brokers, producerConfig)
	if err != nil {
		return nil, err
	}

	client := &MessageSyncProducerClient{
		producer: producer,
		cfg:      cfg,
		tracer:   tracer,
		log:      log,
	}

	log.Info("... started.")
	return client, nil
}

func CommonProducerConfig(cfg *model.Cfg) *sarama.Config {
	//TODO(mk): set cfg from file - is now hardcoded
	//TODO(mk: enable security when publishing to Kafka
	producerConfig := sarama.NewConfig()
	producerConfig.Producer.Return.Successes = true
	producerConfig.Producer.RequiredAcks = sarama.WaitForAll
	producerConfig.Producer.Idempotent = true
	producerConfig.Net.MaxOpenRequests = 1
	producerConfig.Producer.Retry.Max = 3
	producerConfig.Net.SASL.Enable = false
	// ...
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
	//TODO(mk): create header data in this func, ie change func def.
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

// MessageConsumerClient ATTENTION: Start max one instance of consumer client for each service to keep resource usage low
type MessageConsumerClient struct {
	consumerConfig *sarama.Config
	brokers        []string
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	log            *logger.Log
}

func CommonConsumerConfig(cfg *model.Cfg) *sarama.Config {
	//TODO(mk): set cfg from file - is now hardcoded
	//TODO(mk): enable security when consumting from Kafka
	consumerConfig := sarama.NewConfig()
	consumerConfig.Consumer.Offsets.Initial = sarama.OffsetOldest
	consumerConfig.Consumer.Group.Rebalance.GroupStrategies = []sarama.BalanceStrategy{sarama.NewBalanceStrategyRange()}
	consumerConfig.Net.SASL.Enable = false
	// ...
	return consumerConfig
}

func NewMessageConsumerClient(consumerConfig *sarama.Config, brokers []string, log *logger.Log) (*MessageConsumerClient, error) {
	if consumerConfig == nil {
		return nil, errors.New("param consumerConfig is nil")
	}
	if err := consumerConfig.Validate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &MessageConsumerClient{
		consumerConfig: consumerConfig,
		brokers:        brokers,
		ctx:            ctx,
		cancel:         cancel,
		wg:             sync.WaitGroup{},
		log:            log,
	}, nil
}

func (c *MessageConsumerClient) Start(handlerFactory func(string) sarama.ConsumerGroupHandler, handlerConfigs []HandlerConfig) error {
	for _, handlerConfig := range handlerConfigs {
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
					c.log.Error(err, "Error on consumer group", "group", handlerConfig.ConsumerGroup)
					//TODO(mk): use more advanced backoff algorithm?
					time.Sleep(1 * time.Second)
				}

				if c.ctx.Err() != nil {
					c.log.Error(c.ctx.Err(), "Error on consumer group ctx", "group", handlerConfig.ConsumerGroup)
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
	Log      *logger.Log
}

func (cgh *ConsumerGroupHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (cgh *ConsumerGroupHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }

func (cgh *ConsumerGroupHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	if cgh.Handlers == nil {
		cgh.Log.Error(errors.New("No handlers defined"), "No Handlers for any topic")
		//TODO(mk): send to a general error topic?
		return nil
	}

	handler, exists := cgh.Handlers[claim.Topic()]
	if !exists {
		cgh.Log.Error(errors.New("No handler for topic"), "topic", claim.Topic())
		//TODO(mk): send to a general error topic?
		return nil
	}

	handlerType := reflect.TypeOf(handler).String()

	for message := range claim.Messages() {
		var errMessage string

		if err := handler.HandleMessage(session.Context(), message); err != nil {
			cgh.Log.Error(err, "Error handling message", "topic", claim.Topic())
			//TODO(mk): more advanced retry/error handling including send to error topic if not OK after X number of retries
			errMessage = fmt.Sprintf("error handling message: %v", err)
		}

		info := fmt.Sprintf("message consumed by handler type: %s, topic: %s, partition: %d, offset: %d",
			handlerType,
			claim.Topic(),
			message.Partition,
			message.Offset,
		)
		if errMessage != "" {
			info = fmt.Sprintf("%s, error: %s", info, errMessage)
		}
		session.MarkMessage(message, info)
	}
	return nil
}
