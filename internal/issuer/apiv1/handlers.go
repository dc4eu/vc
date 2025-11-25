package apiv1

import (
	"context"
	"fmt"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/gen/registry/apiv1_registry"
	"vc/pkg/helpers"
	"vc/pkg/sdjwtvc"

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
	return nil, nil
}

// CreateCredentialRequest is the request for Credential
type CreateCredentialRequest struct {
	DocumentData []byte            `json:"document_data" validate:"required"`
	Scope        string            `json:"scope" validate:"required"`
	JWK          *apiv1_issuer.Jwk `json:"jwk" validate:"required"`
}

// CreateCredentialReply is the reply for Credential
type CreateCredentialReply struct {
	//Data *sdjwt.PresentationFlat `json:"data"`
	Data []*apiv1_issuer.Credential `json:"data"`
}

// MakeSDJWT creates a credential generically for any credential type
func (c *Client) MakeSDJWT(ctx context.Context, req *CreateCredentialRequest) (*CreateCredentialReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:CreateCredential")
	defer span.End()

	if err := helpers.Check(ctx, c.cfg, req, c.log); err != nil {
		c.log.Debug("Validation", "err", err)
		return nil, err
	}

	// Get credential constructor from config based on credential type
	credentialConstructor := c.cfg.GetCredentialConstructor(req.Scope)
	if credentialConstructor == nil {
		return nil, fmt.Errorf("unsupported scope: %s", req.Scope)
	}

	// VCTM is already in sdjwtvc format
	vctm := credentialConstructor.VCTM
	if vctm == nil {
		return nil, fmt.Errorf("VCTM not configured for scope: %s", req.Scope)
	}

	// Validate document data against VCTM schema
	if err := sdjwtvc.ValidateDocument(req.DocumentData, vctm); err != nil {
		c.log.Error(err, "document validation failed", "scope", req.Scope)
		return nil, fmt.Errorf("document validation failed: %w", err)
	}

	// Build SD-JWT using sdjwtvc package
	sdClient := sdjwtvc.New()
	token, err := sdClient.BuildCredential(
		c.cfg.Issuer.JWTAttribute.Issuer,
		c.kid,
		c.privateKey,
		credentialConstructor.VCT,
		req.DocumentData,
		req.JWK,
		vctm,
		nil, // Use default options
	)
	if err != nil {
		c.log.Error(err, "failed to create sdjwt", "scope", req.Scope)
		return nil, err
	}

	//c.auditLog.AddAuditLog(ctx, "create_credential", signedCredential.PresentationFlat())

	reply := &CreateCredentialReply{
		Data: []*apiv1_issuer.Credential{
			{
				Credential: token,
			},
		},
	}

	return reply, nil
}

// RevokeRequest is the request for GenericRevoke
type RevokeRequest struct {
	AuthenticSource string `json:"authentic_source"`
	VCT             string `json:"vct"`
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
	ctx, span := c.tracer.Start(ctx, "apiv1:Revoke")
	defer span.End()

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

	// AuditLog
	c.auditLog.AddAuditLog(ctx, "revoke", "mura")

	reply := &RevokeReply{
		Data: struct {
			Status bool `json:"status"`
		}{
			Status: resp.Status,
		},
	}
	return reply, nil
}

// JWKS creates a credential
func (c *Client) JWKS(ctx context.Context, in *apiv1_issuer.Empty) (*apiv1_issuer.JwksReply, error) {
	_, span := c.tracer.Start(ctx, "apiv1:JWKS")
	defer span.End()

	keys := &apiv1_issuer.Keys{
		Keys: []*apiv1_issuer.Jwk{
			c.jwkProto,
		},
	}

	reply := &apiv1_issuer.JwksReply{
		Issuer: c.cfg.Issuer.JWTAttribute.Issuer,
		Jwks:   keys,
	}

	return reply, nil
}
