package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/IBM/sarama"
	"log"
	"os"
	"os/signal"
	"vc/internal/mockas/apiv1"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

type EventConsumer struct {
	config *model.Cfg
	logger *logger.Log
	apiv1  Apiv1
	tp     *trace.Tracer
}

func NewEventConsumer(ctx context.Context, config *model.Cfg, api *apiv1.Client, tracer *trace.Tracer, logger *logger.Log) (*EventConsumer, error) {
	ec := &EventConsumer{
		config: config,
		logger: logger,
		apiv1:  api,
		tp:     tracer,
	}
	err := ec.start()
	if err != nil {
		return nil, err
	}
	return ec, nil
}

func (ec *EventConsumer) start() error {
	config := sarama.NewConfig()
	config.Consumer.Offsets.Initial = sarama.OffsetOldest
	config.Consumer.Group.Rebalance.GroupStrategies = []sarama.BalanceStrategy{sarama.NewBalanceStrategyRange()}
	config.Net.SASL.Enable = false // Aktivera SASL-autentisering vid behov
	// ... (övriga säkerhetskonfigurationer)

	consumerGroup, err := sarama.NewConsumerGroup([]string{"kafka0:9092"}, "my-consumer-group-name-1", config)
	if err != nil {
		log.Fatalln("Failed to create consumer group:", err)
	}
	defer consumerGroup.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for err := range consumerGroup.Errors() {
			log.Println("Consumer group error:", err)
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)

	handler := &consumerGroupHandler{
		config: ec.config,
		logger: ec.logger,
		apiv1:  ec.apiv1,
		tp:     ec.tp,
	}

	topics := []string{"topic_mock_next"}

	for {
		err := consumerGroup.Consume(ctx, topics, handler)
		if err != nil {
			log.Println("Error consuming:", err)
		}

		select {
		case <-signals:
			cancel()
			return nil
		default:
		}
	}
}

func (ec *EventConsumer) Close() {
	//TODO: clean up what ever needs to be cleaned up
}

type consumerGroupHandler struct {
	config *model.Cfg
	logger *logger.Log
	apiv1  Apiv1
	tp     *trace.Tracer
}

func (cgh *consumerGroupHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (cgh *consumerGroupHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }

func (cgh *consumerGroupHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for message := range claim.Messages() {
		fmt.Println("Raw message:", message)
		fmt.Println("Raw message as string:", message)
		fmt.Printf("Raw message.Value: %v\n", message.Value)
		fmt.Printf("Message value as string: %s\n", string(message.Value))
		fmt.Printf("Message metadata Partition: %d, Offset: %d, Timestamp: %s, Topic: %s\n",
			message.Partition, message.Offset, message.Timestamp, message.Topic)
		fmt.Println("Headers:")
		if len(message.Headers) > 0 {
			for _, header := range message.Headers {
				fmt.Printf("  %s: %s\n", header.Key, string(header.Value))
			}
		}
		if len(message.Key) > 0 {
			fmt.Printf("Message Key: %s\n", string(message.Key))
		}

		var mockNextRequest apiv1.MockNextRequest
		if err := json.Unmarshal(message.Value, &mockNextRequest); err != nil {
			log.Println("Failed to unmarshal event:", err)
			continue
		}

		fmt.Println("mockNextRequest:", mockNextRequest)
		fmt.Printf("Unmarshaled received: AuthenticSourcePersonId=%s, DocumentType=%s, AuthenticSource=%s\n", mockNextRequest.AuthenticSourcePersonID, mockNextRequest.DocumentType, mockNextRequest.AuthenticSource)

		cgh.apiv1.MockNext(nil, &mockNextRequest)

		// Mark message as treated
		session.MarkMessage(message, "")
	}
	return nil
}
