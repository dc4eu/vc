package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/IBM/sarama"
	"log"
	"os"
	"os/signal"
)

type EventConsumer struct {
}

type Event struct {
	Key     string `json:"key"`
	Payload string `json:"payload"`
}

func NewEventConsumer() *EventConsumer {
	return &EventConsumer{}
}

func (e *EventConsumer) Start() error {
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

	handler := &consumerGroupHandler{}

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

type consumerGroupHandler struct{}

func (h *consumerGroupHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (h *consumerGroupHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }

func (h *consumerGroupHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for message := range claim.Messages() {
		var event Event
		if err := json.Unmarshal(message.Value, &event); err != nil {
			log.Println("Failed to unmarshal event:", err)
			continue
		}

		fmt.Printf("Message received: Key=%s, Payload=%s\n", event.Key, event.Payload)

		//TODO: add logic to handle the event data

		// Mark message as treated
		session.MarkMessage(message, "")
	}
	return nil
}
