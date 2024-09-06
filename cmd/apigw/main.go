package main

import (
	"context"
	"github.com/IBM/sarama"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"vc/internal/apigw/apiv1"
	"vc/internal/apigw/db"
	"vc/internal/apigw/httpserver"
	"vc/internal/apigw/simplequeue"
	"vc/pkg/configuration"
	"vc/pkg/kafka"
	"vc/pkg/kvclient"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

type service interface {
	Close(ctx context.Context) error
}

var GitCommit string

func main() {
	var wg sync.WaitGroup
	ctx := context.Background()

	services := make(map[string]service)

	cfg, err := configuration.Parse(ctx, logger.NewSimple("Configuration"))
	if err != nil {
		panic(err)
	}

	log, err := logger.New("vc_apigw", cfg.Common.Log.FolderPath, cfg.Common.Production)
	if err != nil {
		panic(err)
	}
	tracer, err := trace.New(ctx, cfg, log, "vc", "apigw")
	if err != nil {
		panic(err)
	}

	kvClient, err := kvclient.New(ctx, cfg, tracer, log.New("kvClient"))
	services["kvClient"] = kvClient
	if err != nil {
		panic(err)
	}
	dbService, err := db.New(ctx, cfg, tracer, log.New("db"))
	services["dbService"] = dbService
	if err != nil {
		panic(err)
	}

	simpleQueueService, err := simplequeue.New(ctx, kvClient, tracer, cfg, log.New("queue"))
	services["queueService"] = simpleQueueService
	if err != nil {
		panic(err)
	}

	var kafkaMessageProducer *apiv1.KafkaMessageProducer
	if cfg.Common.Kafka.Enabled {
		// Start max one producer client for each service
		var err error
		kafkaMessageProducer, err = apiv1.NewKafkaMessageProducer(kafka.CommonProducerConfig(cfg), ctx, cfg, tracer, log)
		if err != nil {
			panic(err)
		}
		services["kafkaMessageProducer"] = kafkaMessageProducer
	} else {
		log.Info("Kafka disabled - no Kafka message producer created")
	}

	apiv1Client, err := apiv1.New(ctx, kvClient, dbService, simpleQueueService, tracer, cfg, log.New("apiv1"))
	if err != nil {
		panic(err)
	}
	httpService, err := httpserver.New(ctx, cfg, apiv1Client, tracer, log.New("httpserver"), kafkaMessageProducer)
	services["httpService"] = httpService
	if err != nil {
		panic(err)
	}

	kafkaMessageConsumer, err := startNewKafkaMessangerConsumer(cfg, log, apiv1Client, tracer)
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

	mainLog := log.New("main")
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

func startNewKafkaMessangerConsumer(cfg *model.Cfg, log *logger.Log, apiv1Client *apiv1.Client, tracer *trace.Tracer) (*kafka.MessageConsumerClient, error) {
	if !cfg.Common.Kafka.Enabled {
		log.Info("Kafka disabled - no consumer created")
	}

	kafkaMessageConsumerClient, err := kafka.NewMessageConsumerClient(kafka.CommonConsumerConfig(cfg), cfg.Common.Kafka.Brokers, log.New("kafka_consumer_client"))
	if err != nil {
		return nil, err
	}

	handlerConfigs := []kafka.HandlerConfig{
		{Topic: kafka.TopicUpload, ConsumerGroup: "topic_upload_consumer_group_apigw"},
		// add more handlerconfigs here
	}

	handlerFactory := func(topic string) sarama.ConsumerGroupHandler {
		handlersMap := map[string]kafka.MessageHandler{
			kafka.TopicUpload: &apiv1.UploadMessageHandler{Log: log.New("kafka_upload_handler"), ApiV1: apiv1Client, Tracer: tracer},
			// add more handlers here...
		}
		return &kafka.ConsumerGroupHandler{Handlers: handlersMap, Log: log.New("kafka_consumer_group_handler")}
	}

	if err := kafkaMessageConsumerClient.Start(handlerFactory, handlerConfigs); err != nil {
		return nil, err
	}
	return kafkaMessageConsumerClient, nil
}
