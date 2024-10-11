package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"vc/internal/apigw/apiv1"
	"vc/internal/apigw/db"
	"vc/internal/apigw/httpserver"
	"vc/internal/apigw/inbound"
	"vc/internal/apigw/outbound"
	"vc/pkg/configuration"
	"vc/pkg/logger"
	"vc/pkg/trace"
)

type service interface {
	Close(ctx context.Context) error
}

func main() {
	var (
		wg                 = &sync.WaitGroup{}
		ctx                = context.Background()
		services           = make(map[string]service)
		serviceName string = "apigw"
	)

	cfg, err := configuration.New(ctx)
	if err != nil {
		panic(err)
	}

	log, err := logger.New(serviceName, cfg.Common.Log.FolderPath, cfg.Common.Production)
	if err != nil {
		panic(err)
	}

	// main function log
	mainLog := log.New("main")

	tracer, err := trace.New(ctx, cfg, serviceName, log)
	if err != nil {
		panic(err)
	}

	dbService, err := db.New(ctx, cfg, tracer, log)
	services["dbService"] = dbService
	if err != nil {
		panic(err)
	}

	var eventPublisher apiv1.EventPublisher
	if cfg.IsAsyncEnabled(mainLog) {
		var err error
		eventPublisher, err = outbound.New(ctx, cfg, tracer, log)
		services["eventPublisher"] = eventPublisher
		if err != nil {
			panic(err)
		}
	}

	apiv1Client, err := apiv1.New(ctx, dbService, tracer, cfg, log)
	if err != nil {
		panic(err)
	}

	httpService, err := httpserver.New(ctx, cfg, apiv1Client, tracer, eventPublisher, log)
	services["httpService"] = httpService
	if err != nil {
		panic(err)
	}

	if cfg.IsAsyncEnabled(mainLog) {
		eventConsumer, err := inbound.New(ctx, cfg, apiv1Client, tracer, log.New("eventConsumer"))
		services["eventConsumer"] = eventConsumer
		if err != nil {
			panic(err)
		}
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
