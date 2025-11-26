package apiv1

import (
	"context"
	"encoding/json"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/helpers"
	"vc/pkg/model"
	"vc/pkg/vcclient"
)

// CredentialRequest is the request for Credential
type CredentialRequest struct {
	AuthenticSource string            `json:"authentic_source" validate:"required"`
	Identity        *model.Identity   `json:"identity" validate:"required"`
	Scope           string            `json:"scope" validate:"required"`
	VCT             string            `json:"vct" validate:"required"`
	CollectID       string            `json:"collect_id" validate:"required"`
	JWK             *apiv1_issuer.Jwk `json:"jwk" validate:"required"`
}

func (c *Client) SatosaCredential(ctx context.Context, req *CredentialRequest) (*apiv1_issuer.MakeSDJWTReply, error) {
	document, _, err := c.datastoreClient.Document.CollectID(ctx, &vcclient.DocumentCollectIDQuery{
		AuthenticSource: req.AuthenticSource,
		VCT:             req.VCT,
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

	// Use the pre-initialized gRPC client
	reply, err := c.issuerClient.MakeSDJWT(ctx, &apiv1_issuer.MakeSDJWTRequest{
		Scope:        req.Scope,
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

	// Use the pre-initialized gRPC client
	resp, err := c.issuerClient.JWKS(ctx, &apiv1_issuer.Empty{})
	if err != nil {
		return nil, err
	}

	return resp, nil
}
