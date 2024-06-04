package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"vc/internal/issuer/apiv1"
	"vc/internal/issuer/auditlog"
	"vc/internal/issuer/db"
	"vc/internal/issuer/grpcserver"
	"vc/internal/issuer/httpserver"
	"vc/internal/issuer/simplequeue"
	"vc/pkg/configuration"
	"vc/pkg/kvclient"
	"vc/pkg/logger"
	"vc/pkg/rpcclient"
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

	log, err := logger.New("vc_issuer", cfg.Common.Log.FolderPath, cfg.Common.Production)
	if err != nil {
		panic(err)
	}
	tracer, err := trace.New(ctx, cfg, log, "vc", "issuer")
	if err != nil {
		panic(err)
	}

	auditLogService, err := auditlog.New(ctx, cfg, log.New("auditlog"))
	services["auditLogService"] = auditLogService
	if err != nil {
		panic(err)
	}

	rpcClients, err := rpcclient.New(cfg, log.New("rpc"))
	if err != nil {
		panic(err)
	}
	dbService, err := db.New(ctx, cfg, tracer, log.New("db"))
	services["dbService"] = dbService
	if err != nil {
		panic(err)
	}
	kvClient, err := kvclient.New(ctx, cfg, tracer, log.New("kvClient"))
	services["kvClient"] = kvClient
	if err != nil {
		panic(err)
	}

	simpleQueueService, err := simplequeue.New(ctx, kvClient, tracer, cfg, log.New("queue"))
	services["queueService"] = simpleQueueService
	if err != nil {
		panic(err)
	}

	apiv1Client, err := apiv1.New(ctx, simpleQueueService, rpcClients, kvClient, dbService, auditLogService, cfg, tracer, log.New("apiv1"))
	if err != nil {
		panic(err)
	}
	httpService, err := httpserver.New(ctx, cfg, apiv1Client, tracer, log.New("httpserver"))
	services["httpService"] = httpService
	if err != nil {
		panic(err)
	}
	grpcService, err := grpcserver.New(ctx, cfg, apiv1Client, log.New("grpcserver"))
	services["grpcService"] = grpcService
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
