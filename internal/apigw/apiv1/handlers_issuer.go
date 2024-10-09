package apiv1

import (
	"context"
	"encoding/json"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/gen/registry/apiv1_registry"
	"vc/pkg/datastoreclient"
	"vc/pkg/helpers"
	"vc/pkg/model"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// CredentialRequest is the request for Credential
type CredentialRequest struct {
	AuthenticSource string          `json:"authentic_source" validate:"required"`
	Identity        *model.Identity `json:"identity" validate:"required"`
	DocumentType    string          `json:"document_type" validate:"required"`
	CredentialType  string          `json:"credential_type" validate:"required"`
	CollectID       string          `json:"collect_id" validate:"required"`
}

// Credential makes a credential
//
//	@Summary		Credential
//	@ID				create-credential
//	@Description	Create credential endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	apiv1_issuer.MakeSDJWTReply	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse		"Bad Request"
//	@Param			req	body		CredentialRequest			true	" "
//	@Router			/credential [post]
func (c *Client) Credential(ctx context.Context, req *CredentialRequest) (*apiv1_issuer.MakeSDJWTReply, error) {
	if err := helpers.Check(ctx, c.cfg, req, c.log); err != nil {
		return nil, err
	}

	document, _, err := c.datastoreClient.DocumentService.CollectID(ctx, &datastoreclient.DocumentCollectIDQuery{
		AuthenticSource: req.AuthenticSource,
		DocumentType:    req.DocumentType,
		CollectID:       req.CollectID,
		Identity:        req.Identity,
	})
	if err != nil {
		return nil, err
	}

	if document == nil || document.DocumentData == nil {
		return nil, helpers.ErrNoDocumentFound
	}

	documentData, err := json.Marshal(document.DocumentData)
	if err != nil {
		return nil, err
	}

	// Build SDJWT
	conn, err := grpc.NewClient(c.cfg.Issuer.GRPCServer.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.log.Error(err, "Failed to connect to issuer")
		return nil, err
	}
	defer conn.Close()
	client := apiv1_issuer.NewIssuerServiceClient(conn)

	reply, err := client.MakeSDJWT(ctx, &apiv1_issuer.MakeSDJWTRequest{
		DocumentType: req.DocumentType,
		DocumentData: documentData,
	})
	if err != nil {
		c.log.Error(err, "failed to call MakeSDJWT")
		return nil, err
	}

	return reply, nil
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

	conn, err := grpc.NewClient(c.cfg.Registry.GRPCServer.Addr, optInsecure)
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
