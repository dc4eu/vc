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
	"vc/internal/issuer/httpserver"
	"vc/pkg/configuration"
	"vc/pkg/logger"
)

type service interface {
	Close(ctx context.Context) error
}

func main() {
	wg := &sync.WaitGroup{}
	ctx := context.Background()

	var (
		log      *logger.Logger
		mainLog  *logger.Logger
		services = make(map[string]service)
	)

	cfg, err := configuration.Parse(logger.NewSimple("Configuration"))
	if err != nil {
		panic(err)
	}

	mainLog = logger.New("main", cfg.Common.Production)
	log = logger.New("vc_issuer", cfg.Common.Production)

	db, err := db.New(ctx, cfg, log.New("db"))
	services["db"] = db
	if err != nil {
		panic(err)
	}
	sunetCA, err := ca.New(ctx, cfg, log.New("ca"))
	if err != nil {
		panic(err)
	}
	apiv1, err := apiv1.New(ctx, sunetCA, db, cfg, log.New("apiv1"))
	if err != nil {
		panic(err)
	}
	httpserver, err := httpserver.New(ctx, cfg, apiv1, log.New("httpserver"))
	services["httpserver"] = httpserver
	if err != nil {
		panic(err)
	}

	// Handle sigterm and await termChan signal
	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)

	<-termChan // Blocks here until interrupted

	mainLog.Info("HALTING SIGNAL!")

	for serviceName, service := range services {
		if err := service.Close(ctx); err != nil {
			mainLog.Warn("serviceName", serviceName, "error", err)
		}
	}

	wg.Wait() // Block here until are workers are done

	mainLog.Info("Stopped")
}
