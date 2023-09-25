package apiv1

import (
	"context"
	"fmt"
	"vc/internal/registry/apiv1"
	"vc/pkg/pda1"
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

	var rpcReply apiv1.AddReply
	c.log.Info("calling rpc server 2")
	if err := c.rpcClient.SingleCall("registry", "Add", apiv1.AddRequest{Entity: "mura"}, &rpcReply); err != nil {
		fmt.Println("here", err)
		return nil, err
	}
	c.log.Info("rpc reply", "reply", rpcReply)

	reply := &GetReply{
		JWT: jwt,
	}
	return reply, nil
}
