package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"vc/internal/datastore/apiv1"
	"vc/internal/datastore/db"
	"vc/internal/datastore/httpserver"
	"vc/pkg/configuration"
	"vc/pkg/logger"
	"vc/pkg/trace"
)

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

	log, err := logger.New("vc_datastore", cfg.Common.Log.FolderPath, cfg.Common.Production)
	if err != nil {
		panic(err)
	}

	tracer, err := trace.New(ctx, cfg, log, "vc_cache", "cache")
	if err != nil {
		panic(err)
	}

	dbService, err := db.New(ctx, cfg, log.New("db"))
	services["dbService"] = dbService
	if err != nil {
		panic(err)
	}
	apiClient, err := apiv1.New(ctx, dbService, cfg, log.New("apiv1"))
	if err != nil {
		panic(err)
	}
	httpService, err := httpserver.New(ctx, cfg, apiClient, log.New("httpserver"))
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
