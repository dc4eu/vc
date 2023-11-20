package apiv1

import (
	"context"
	apiv1_registry "vc/internal/gen/registry/apiv1.registry"
	"vc/pkg/pda1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GetRequest holds the request
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

// Get gets a credential
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

type CredentialRequest struct {
	AuthenticSource string `json:"authentic_source" binding:"required"`
	DocumentID      string `json:"document_id" binding:"required"`
	DocumentType    string `json:"document_type" binding:"required"`
	CollectID       string `json:"collect_id" binding:"required"`
	DateOfBirth     string `json:"date_of_birth" binding:"required"`
	LastName        string `json:"last_name" binding:"required"`
	FirstName       string `json:"first_name" binding:"required"`
	UID             string `json:"uid" binding:"required"`
}

type CredentialReply struct {
	SDJWT string `json:"sdjwt"`
}

func (c *Client) Credential(ctx context.Context, req *CredentialRequest) (*CredentialReply, error) {
	// IDMapping

	// GetDocument

	// Build SDJWT
	return nil, nil
}

// RevokeRequest is the request for GenericRevoke
type RevokeRequest struct {
	AuthenticSource string `json:"authentic_source"`
	DocumentType    string `json:"document_type"`
	DocumentID      string `json:"document_id"`
	RevocationID    string `json:"revocation_id"`
}

// RevokeReply is the reply for GenericRevoke
type RevokeReply struct {
	Data struct {
		Status bool `json:"status"`
	}
}

// Revoke revokes a document
//
//	@Summary		Revoke
//	@ID				generic-revoke
//	@Description	Revoke endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	RevokeReply				"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		RevokeRequest			true	" "
//	@Router			/revoke [post]
func (c *Client) Revoke(ctx context.Context, req *RevokeRequest) (*RevokeReply, error) {
	optInsecure := grpc.WithTransportCredentials(insecure.NewCredentials())

	conn, err := grpc.Dial(c.cfg.Registry.RPCServer.Addr, optInsecure)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := apiv1_registry.NewRegistryServiceClient(conn)
	resp, err := client.Revoke(ctx, &apiv1_registry.RevokeRequest{
		Entity: "mura",
	})
	if err != nil {
		return nil, err
	}

	reply := &RevokeReply{
		Data: struct {
			Status bool `json:"status"`
		}{
			Status: resp.Status,
		},
	}
	return reply, nil
}
