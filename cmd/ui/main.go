package main

import (
	"context"
	"encoding/gob"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"vc/internal/ui/apiv1"
	"vc/internal/ui/httpserver"
	"vc/pkg/configuration"
	"vc/pkg/logger"
	"vc/pkg/trace"
)

func init() {
	// Needed to serialize/deserialize time.Time in the session and cookie
	gob.Register(time.Time{})
}

type service interface {
	Close(ctx context.Context) error
}

func main() {
	wg := &sync.WaitGroup{}
	ctx := context.Background()

	services := make(map[string]service)

	cfg, err := configuration.Parse(ctx, logger.NewSimple("Configuration"))
	if err != nil {
		panic(err)
	}

	log, err := logger.New("vc_ui", cfg.Common.Log.FolderPath, cfg.Common.Production)
	if err != nil {
		panic(err)
	}

	tracer, err := trace.New(ctx, cfg, log, "vc", "ui")
	if err != nil {
		panic(err)
	}

	apiClient, err := apiv1.New(ctx, cfg, tracer, log.New("ui_api_client"))
	services["apiClient"] = apiClient
	if err != nil {
		panic(err)
	}

	httpService, err := httpserver.New(ctx, cfg, apiClient, tracer, log.New("httpserver"))
	services["httpService"] = httpService
	if err != nil {
		panic(err)
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
