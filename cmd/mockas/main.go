package main

import (
	"context"
	"github.com/IBM/sarama"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"vc/internal/mockas/apiv1"
	"vc/internal/mockas/httpserver"
	"vc/pkg/configuration"
	"vc/pkg/kafka"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

type service interface {
	Close(ctx context.Context) error
}

func main() {
	var wg sync.WaitGroup
	ctx := context.Background()

	services := make(map[string]service)

	cfg, err := configuration.Parse(ctx, logger.NewSimple("Configuration"))
	if err != nil {
		panic(err)
	}

	log, err := logger.New("vc_mock_as", cfg.Common.Log.FolderPath, cfg.Common.Production)
	if err != nil {
		panic(err)
	}
	mainLog := log.New("main")

	tracer, err := trace.New(ctx, cfg, log, "vc", "mock_as")
	if err != nil {
		panic(err)
	}

	apiv1Client, err := apiv1.New(ctx, cfg, tracer, log.New("apiv1"))
	if err != nil {
		panic(err)
	}

	httpService, err := httpserver.New(ctx, cfg, apiv1Client, tracer, log.New("httpserver"))
	services["httpService"] = httpService
	if err != nil {
		panic(err)
	}

	kafkaMessageConsumer, err := startNewKafkaMessangerConsumerClient(cfg, log, apiv1Client, tracer)
	if err != nil {
		panic(err)
	}
	if kafkaMessageConsumer != nil {
		services["kafkaMessageConsumer"] = kafkaMessageConsumer
	}

	// Handle sigterm and await termChan signal
	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)

	<-termChan // Blocks here until interrupted

	mainLog.Info("HALTING SIGNAL!")

	for serviceName, service := range services {
		if err := service.Close(ctx); err != nil {
			mainLog.Trace("serviceName", serviceName, "error", err)
		}
	}

	if err := tracer.Shutdown(ctx); err != nil {
		mainLog.Error(err, "Tracer shutdown")
	}

	wg.Wait() // Block here until are workers are done

	mainLog.Info("Stopped")
}

func startNewKafkaMessangerConsumerClient(cfg *model.Cfg, log *logger.Log, apiv1Client *apiv1.Client, tracer *trace.Tracer) (*kafka.MessageConsumerClient, error) {
	if !cfg.Common.Kafka.Enabled {
		log.Info("Kafka disabled - no consumer created")
	}

	handlerConfigs := []kafka.HandlerConfig{
		{Topic: kafka.TopicMockNext, ConsumerGroup: "topic_mock_next_consumer_group_mockas"},
		{Topic: kafka.TopicUpload, ConsumerGroup: "topic_upload_consumer_group_mockas"},
		// add more handlerconfigs here
	}

	kafkaMessageConsumerClient, err := kafka.NewMessageConsumerClient(kafka.CommonConsumerConfig(), cfg.Common.Kafka.Brokers, handlerConfigs, log.New("kafka_consumer_client"))
	if err != nil {
		return nil, err
	}

	handlerFactory := func(topic string) sarama.ConsumerGroupHandler {
		handlersMap := map[string]kafka.MessageHandler{
			kafka.TopicMockNext: &apiv1.MockNextMessageHandler{Log: log.New("kafka_mock_next_handler"), ApiV1: apiv1Client, Tracer: tracer},
			kafka.TopicUpload:   &apiv1.UploadMessageHandler{Log: log.New("kafka_upload_handler"), ApiV1: apiv1Client, Tracer: tracer},
			// add more handlers here...
		}
		return &kafka.ConsumerGroupHandler{Handlers: handlersMap}
	}

	if err := kafkaMessageConsumerClient.Start(handlerFactory); err != nil {
		return nil, err
	}
	return kafkaMessageConsumerClient, nil
}
