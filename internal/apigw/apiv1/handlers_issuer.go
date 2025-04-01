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
	AuthenticSource string            `json:"authentic_source" validate:"required"`
	Identity        *model.Identity   `json:"identity" validate:"required"`
	DocumentType    string            `json:"document_type" validate:"required"`
	CredentialType  string            `json:"credential_type" validate:"required"`
	CollectID       string            `json:"collect_id" validate:"required"`
	JWK             *apiv1_issuer.Jwk `json:"jwk" validate:"required"`
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
	document, _, err := c.datastoreClient.Document.CollectID(ctx, &datastoreclient.DocumentCollectIDQuery{
		AuthenticSource: req.AuthenticSource,
		DocumentType:    req.DocumentType,
		CollectID:       req.CollectID,
		Identity:        req.Identity,
	})
	if err != nil {
		c.log.Debug("failed to get document", "error", err)
		return nil, err
	}

	if document == nil || document.DocumentData == nil {
		c.log.Debug("document_data not found")
		return nil, helpers.ErrNoDocumentFound
	}

	c.log.Debug("document", "document", document)

	documentData, err := json.Marshal(document.DocumentData)
	if err != nil {
		c.log.Debug("failed to marshal document data", "error", err)
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
		Jwk:          req.JWK,
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

// JWKS returns the public key in JWK format
//
//	@Summary		JWKS
//	@ID				issuer-JWKS
//	@Description	JWKS endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	apiv1_issuer.JwksReply	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Router			/credential/.well-known/jwks [get]
func (c *Client) JWKS(ctx context.Context) (*apiv1_issuer.JwksReply, error) {
	c.log.Debug("jwk")
	optInsecure := grpc.WithTransportCredentials(insecure.NewCredentials())

	conn, err := grpc.NewClient(c.cfg.Issuer.GRPCServer.Addr, optInsecure)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := apiv1_issuer.NewIssuerServiceClient(conn)
	resp, err := client.JWKS(ctx, &apiv1_issuer.Empty{})
	if err != nil {
		return nil, err
	}

	return resp, nil
}
