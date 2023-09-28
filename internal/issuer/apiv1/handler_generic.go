package apiv1

import (
	"context"
	apiv1_registry "vc/internal/gen/registry/apiv1.registry"
	"vc/pkg/pda1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type GetRequest struct {
	FirstName       string `json:"first_name"`
	LastName        string `json:"last_name"`
	BirthDate       string `json:"birth_date"`
	AuthenticSource string `json:"authentic_source"`
}

// GetReply is the reply
type GetReply struct {
	JWT string `json:"jwt"`
}

func (c *Client) Get(ctx context.Context, indata *GetRequest) (*GetReply, error) {
	doc := &pda1.Document{}
	jwt, err := c.pda1.Build(doc, "mura")
	if err != nil {
		return nil, err
	}

	optInsecure := grpc.WithTransportCredentials(insecure.NewCredentials())
	//optServiceConfig := grpc.WithDefaultServiceConfig(clientConfig)

	conn, err := grpc.Dial(c.cfg.Registry.RPCServer.Addr, optInsecure)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := apiv1_registry.NewRegistryServiceClient(conn)
	req := apiv1_registry.AddRequest{
		Entity: "mura",
	}
	resp, err := client.Add(ctx, &req)
	if err != nil {
		return nil, err
	}

	c.log.Info("rpc reply", "reply", resp)

	reply := &GetReply{
		JWT: jwt,
	}
	return reply, nil
}
