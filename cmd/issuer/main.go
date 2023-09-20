package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"vc/internal/issuer/apiv1"
	"vc/internal/issuer/ca"
	"vc/internal/issuer/db"
	"vc/internal/issuer/ehic"
	"vc/internal/issuer/httpserver"
	"vc/internal/issuer/kv"
	"vc/internal/issuer/pda1"
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

	log, err := logger.New("vc_issuer", cfg.Common.Log.FolderPath, cfg.Common.Production)
	if err != nil {
		panic(err)
	}

	dbService, err := db.New(ctx, cfg, log.New("db"))
	services["dbService"] = dbService
	if err != nil {
		panic(err)
	}
	kvService, err := kv.New(ctx, cfg, log.New("keyvalue"))
	services["kvService"] = kvService
	if err != nil {
		panic(err)
	}
	caClient, err := ca.New(ctx, kvService, dbService, cfg, log.New("ca"))
	if err != nil {
		panic(err)
	}
	ehicService, err := ehic.New(ctx, cfg, log.New("ehic"))
	services["ehicService"] = ehicService
	if err != nil {
		panic(err)
	}
	pda1Service, err := pda1.New(ctx, cfg, log.New("pda1"))
	services["pda1Service"] = pda1Service
	if err != nil {
		panic(err)
	}
	apiv1Client, err := apiv1.New(ctx, caClient, kvService, dbService, cfg, log.New("apiv1"))
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
			mainLog.Trace("serviceName", serviceName, "error", err)
		}
	}

	wg.Wait() // Block here until are workers are done

	mainLog.Info("Stopped")
}
