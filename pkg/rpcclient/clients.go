package rpcclient

import (
	"errors"
	"fmt"
	"net/rpc"
	"vc/pkg/logger"
	"vc/pkg/model"
)

type Client struct {
	log *logger.Log
	rpc map[string]config
}

type config struct {
	addr           string
	v1             string
	statusEndpoint string
}

// New creates a new rpc client for each service in the config file
func New(cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		log: log,
		rpc: map[string]config{
			"issuer": {
				addr:           cfg.Issuer.GRPCServer.Addr,
				v1:             "IssuerV1",
				statusEndpoint: "IssuerV1.Health",
			},
			"registry": {
				addr:           cfg.Registry.GRPCServer.Addr,
				v1:             "RegistryV1",
				statusEndpoint: "RegistryV1.Health",
			},
			"verifier": {
				addr:           cfg.Verifier.GRPCServer.Addr,
				v1:             "VerifierV1",
				statusEndpoint: "VerifierV1.Health",
			},
			"datastore": {
				addr:           cfg.Datastore.GRPCServer.Addr,
				v1:             "DatastoreV1",
				statusEndpoint: "DatastoreV1.Health",
			},
		},
	}

	return c, nil
}

// SingleCall calls the rpc server
func (c *Client) SingleCall(server, method string, args, reply any) error {
	c.log.Info("calling rpc server", "server", server, "endpoint", method)

	service, ok := c.rpc[server]
	if !ok {
		return errors.New("service not found")
	}

	rpcClient, err := rpc.DialHTTP("tcp", service.addr)
	if err != nil {
		return err
	}
	defer rpcClient.Close()

	serviceMethod := fmt.Sprintf("%s.%s", service.v1, method)
	err = rpcClient.Call(serviceMethod, args, reply)
	if err != nil {
		return err
	}

	return nil
}
