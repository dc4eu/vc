package apiv1

import (
	"context"
	"encoding/json"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/helpers"
	"vc/pkg/model"
	"vc/pkg/vcclient"

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

func (c *Client) SatosaCredential(ctx context.Context, req *CredentialRequest) (*apiv1_issuer.MakeSDJWTReply, error) {
	document, _, err := c.datastoreClient.Document.CollectID(ctx, &vcclient.DocumentCollectIDQuery{
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

// JWKS returns the public key in JWK format
// @Summary		JWKS
// @ID				issuer-JWKS
// @Description	JWKS endpoint
// @Tags			dc4eu
// @Accept			json
// @Produce		json
// @Success		200	{object}	apiv1_issuer.JwksReply	"Success"
// @Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
// @Router			/credential/.well-known/jwks [get]
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
