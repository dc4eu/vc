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

	if cfg.Common.Kafka.Enabled {
		//kafkaConsumer, err := httpserver.NewKafkaConsumer(&ctx, cfg, apiv1Client, tracer, log.New("kafka_consumer"))
		//-------------------------------------------------
		saramaConfig := sarama.NewConfig()
		saramaConfig.Consumer.Offsets.Initial = sarama.OffsetOldest
		saramaConfig.Consumer.Group.Rebalance.GroupStrategies = []sarama.BalanceStrategy{sarama.NewBalanceStrategyRange()}
		saramaConfig.Net.SASL.Enable = false //TODO: Aktivera SASL-auth när det behövs

		topicConfigs := []kafka.KafkaTopicConfig{
			{Topic: kafka.TopicMockNextName, ConsumerGroup: "topic_mock_next_consumer_group_mockas"},
			//{Topic: "topic2", ConsumerGroup: "consumer_group2"},
		}

		baseConsumer, err := kafka.NewBaseKafkaConsumer(cfg.Common.Kafka.Brokers, topicConfigs, saramaConfig)
		if err != nil {
			// Hantera fel
			panic(err)
		}

		// Factory-funktion för att skapa specifika handlers för varje topic
		handlerFactory := func(topic string) sarama.ConsumerGroupHandler {
			handlersMap := map[string]kafka.MessageHandler{
				kafka.TopicMockNextName: &httpserver.MockNextHandler{Log: log.New("kafka_mock_next_handler"), ApiV1: apiv1Client, Tracer: tracer},
				// Lägg till fler handlers om det behövs
			}
			return &kafka.ConsumerGroupHandler{Handlers: handlersMap}
		}

		// Starta konsumenten med specifika handlers
		if err := baseConsumer.Start(handlerFactory); err != nil {
			// Hantera fel
			panic(err)
		}
		//-------------------------------------------------
		//if err != nil {
		//	panic(err)
		//}
		services["kafkaConsumer"] = baseConsumer
	} else {
		log.Info("Kafka disabled - no consumer created")
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
