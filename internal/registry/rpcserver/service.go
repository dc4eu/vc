package rpcserver

import (
	"context"
	"net/http"
	"net/rpc"
	"vc/internal/registry/apiv1"
	"vc/pkg/logger"
	"vc/pkg/model"
)

// Service is the service object for rpcserver
type Service struct {
	apiv1      Apiv1
	log        *logger.Log
	cfg        *model.Cfg
	server     *http.Server
	handler    *V1
	probeStore *model.ProbeStore
}

// New creates a new rpcserver service
func New(ctx context.Context, api *apiv1.Client, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	s := &Service{
		log:    log,
		cfg:    cfg,
		server: &http.Server{Addr: cfg.Registry.RPCServer.Addr},
	}

	s.handler = &V1{
		log:   log,
		apiv1: api,
	}

	if err := rpc.RegisterName("RegistryV1", s.handler); err != nil {
		s.log.Error(err, "Error while registering rpc handler")
	}
	rpc.HandleHTTP()

	// Run http server
	go func() {
		err := s.server.ListenAndServe()
		if err != nil {
			s.log.New("http").Trace("listen_error", "error", err)
		}
	}()
	s.log.Info("Started")

	return s, nil
}

// Status returns the status of the database
//func (s *Service) Status(ctx context.Context) *model.Probe {
//	if time.Now().Before(s.probeStore.NextCheck) {
//		return s.probeStore.PreviousResult
//	}
//	probe := &model.Probe{
//		Name:          "kv",
//		Healthy:       true,
//		Message:       "OK",
//		LastCheckedTS: time.Now(),
//	}
//
//	s.server
//	_, err := c.redisClient.Ping(ctx).Result()
//	if err != nil {
//		probe.Message = err.Error()
//		probe.Healthy = false
//	}
//	c.probeStore.PreviousResult = probe
//	c.probeStore.NextCheck = time.Now().Add(time.Second * 10)
//
//	return probe
//}

// Close closes the service
func (s *Service) Close(ctx context.Context) error {
	return nil
}
