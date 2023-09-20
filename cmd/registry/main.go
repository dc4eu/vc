package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"vc/internal/registry/apiv1"
	"vc/internal/registry/db"
	"vc/internal/registry/httpserver"
	"vc/internal/registry/tree"
	"vc/pkg/configuration"
	"vc/pkg/logger"
)

type service interface {
	Close(ctx context.Context) error
}

func main() {
	wg := &sync.WaitGroup{}
	ctx := context.Background()

	services := make(map[string]service)

	cfg, err := configuration.Parse(logger.NewSimple("Configuration"))
	if err != nil {
		panic(err)
	}

	log, err := logger.New("vc_registry", cfg.Common.Log.FolderPath, cfg.Common.Production)
	if err != nil {
		panic(err)
	}

	dbService, err := db.New(ctx, cfg, log.New("db"))
	services["dbService"] = dbService
	if err != nil {
		panic(err)
	}

	treeService, err := tree.New(ctx, wg, dbService, cfg, log.New("tree"))
	services["treeService"] = treeService
	if err != nil {
		panic(err)
	}

	apiv1Client, err := apiv1.New(ctx, cfg, treeService, log.New("apiv1"))
	if err != nil {
		panic(err)
	}
	httpService, err := httpserver.New(ctx, cfg, apiv1Client, log.New("httpserver"))
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
			mainLog.Error(err, "serviceName", serviceName)
		}
	}

	wg.Wait() // Block here until are workers are done

	mainLog.Info("Stopped")
}
