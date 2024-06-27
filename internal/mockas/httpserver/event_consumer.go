package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/IBM/sarama"
	"os"
	"os/signal"
	"syscall"
	"time"
	"vc/internal/mockas/apiv1"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

type EventConsumer struct {
	config *model.Cfg
	logger *logger.Log
	apiv1  *apiv1.Client
	tp     *trace.Tracer
	ctx    *context.Context
}

func NewEventConsumer(ctx *context.Context, config *model.Cfg, api *apiv1.Client, tracer *trace.Tracer, logger *logger.Log) (*EventConsumer, error) {
	ec := &EventConsumer{
		config: config,
		logger: logger,
		apiv1:  api,
		tp:     tracer,
		ctx:    ctx,
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

	brokers := []string{"kafka0:9092", "kafka1:9092"}
	consumerGroup, err := sarama.NewConsumerGroup(brokers, "my-consumer-group-name-1", config)
	if err != nil {
		ec.logger.Error(err, "Failed to create consumer group")
		return err

	}
	defer consumerGroup.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for err := range consumerGroup.Errors() {
			ec.logger.Error(err, "Consumer group error")
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	handler := &consumerGroupHandler{
		config: ec.config,
		logger: ec.logger,
		apiv1:  ec.apiv1,
		tp:     ec.tp,
		ctx:    ec.ctx,
	}

	topics := []string{"topic_mock_next"}

	go func() {
		for {
			if err := consumerGroup.Consume(ctx, topics, handler); err != nil {
				ec.logger.Error(err, "Error consuming")
				time.Sleep(1 * time.Second) // Simple retry mechanism
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()

	<-signals
	ec.logger.Info("Received termination signal, shutting down gracefully...")
	cancel()
	time.Sleep(5 * time.Second) // Allow time for shutdown
	return nil
}

func (ec *EventConsumer) Close() {
	//TODO: clean up what ever needs to be cleaned up
}

type consumerGroupHandler struct {
	config *model.Cfg
	logger *logger.Log
	apiv1  *apiv1.Client
	tp     *trace.Tracer
	ctx    *context.Context
}

// Setup is called before the session starts, prior to message consumption.
func (cgh *consumerGroupHandler) Setup(_ sarama.ConsumerGroupSession) error { return nil }

// Cleanup is called after the session ends, after message consumption has stopped.
func (cgh *consumerGroupHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }

// ConsumeClaim must start a consumption loop. The code in this method should keep consuming messages
// from the claim.Messages() channel and call session.MarkMessage for each message consumed.
func (cgh *consumerGroupHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for message := range claim.Messages() {
		printMessageInfo(message)

		var mockNextRequest apiv1.MockNextRequest
		if err := json.Unmarshal(message.Value, &mockNextRequest); err != nil {
			cgh.logger.Error(err, "Failed to unmarshal event")
			//TODO replace with cgh.handleErrorMessage(session, message, err)
			continue
		}

		cgh.logger.Debug("mockNextRequest:", "", mockNextRequest)

		_, err := cgh.apiv1.MockNext(*cgh.ctx, &mockNextRequest)
		if err != nil {
			cgh.logger.Error(err, "Failed to mock next")
			//TODO replace handleErrorMessage(session, message, err) and send to topic_mock_next_error
		}

		// Mark message as treated
		session.MarkMessage(message, "")
	}
	return nil
}

func printMessageInfo(message *sarama.ConsumerMessage) {
	//TODO: change to debug logging
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
}

//TODO: one possible solution when failing to processes a consumed message
//func (cgh *consumerGroupHandler) handleErrorMessage(session sarama.ConsumerGroupSession, message *sarama.ConsumerMessage, err error) {
//	retries := 0
//
//	for retries < cgh.retryLimit {
//		time.Sleep(cgh.retryBackoff)
//		retries++
//
//		// Retry message processing
//		var mockNextRequest apiv1.MockNextRequest
//		if err := json.Unmarshal(message.Value, &mockNextRequest); err != nil {
//			cgh.logger.Errorf("Retry %d: Failed to unmarshal event: %v", retries, err)
//			continue
//		}
//
//		_, err := cgh.apiv1.MockNext(nil, &mockNextRequest)
//		if err != nil {
//			cgh.logger.Errorf("Retry %d: Failed to mock next: %v", retries, err)
//			continue
//		}
//
//		// Successful processing, mark the message
//		session.MarkMessage(message, "")
//		return
//	}
//
//	// If retries exceeded, send to DLQ
//	cgh.sendToDLQ(message)
//}
//
//func (cgh *consumerGroupHandler) sendToDLQ(message *sarama.ConsumerMessage) {
//	// Implement DLQ logic here, e.g., producing to a DLQ topic
//	dlqProducer, err := sarama.NewSyncProducer([]string{cgh.config.KafkaBrokers}, nil)
//	if err != nil {
//		cgh.logger.Errorf("Failed to create DLQ producer: %v", err)
//		return
//	}
//	defer dlqProducer.Close()
//
//	dlqMessage := &sarama.ProducerMessage{
//		Topic: "topic_mock_next_error",
//		Key:   sarama.ByteEncoder(message.Key),
//		Value: sarama.ByteEncoder(message.Value),
//	}
//
//	_, _, err = dlqProducer.SendMessage(dlqMessage)
//	if err != nil {
//		cgh.logger.Error(err,"Failed to send message to DLQ")
//	}
//}

//TODO: möjlig hantering av omprövning från error topic, sätt även time to live så att ex. ett event tas bort säg efter 1 dygn eller liknande?
//for {
//// Tidpunkt A
//startTime := time.Now()
//
//// Hämta alla olästa meddelanden
//for message := range claim.Messages() {
//// ... (bearbeta meddelande) ...
//session.MarkMessage(message, "") // Markera meddelandet som läst
//}
//
//// Beräkna återstående tid till nästa timme
//timeToNextHour := time.Hour - time.Since(startTime)
//
//// Vänta tills nästa timme
//if timeToNextHour > 0 {
//time.Sleep(timeToNextHour)
//}
//}
