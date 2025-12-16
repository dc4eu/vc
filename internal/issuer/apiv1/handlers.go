package apiv1

import (
	"context"
	"fmt"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/gen/registry/apiv1_registry"
	"vc/pkg/helpers"
	"vc/pkg/sdjwtvc"
)

// CreateCredentialRequest is the request for Credential
type CreateCredentialRequest struct {
	DocumentData []byte            `json:"document_data" validate:"required"`
	Scope        string            `json:"scope" validate:"required"`
	JWK          *apiv1_issuer.Jwk `json:"jwk" validate:"required"`
}

// CreateCredentialReply is the reply for Credential
type CreateCredentialReply struct {
	//Data *sdjwt.PresentationFlat `json:"data"`
	Data                   []*apiv1_issuer.Credential `json:"data"`
	TokenStatusListSection int64                      `json:"token_status_list_section"`
	TokenStatusListIndex   int64                      `json:"token_status_list_index"`
}

// MakeSDJWT creates a credential generically for any credential type
func (c *Client) MakeSDJWT(ctx context.Context, req *CreateCredentialRequest) (*CreateCredentialReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:CreateCredential")
	defer span.End()

	c.log.Debug("MakeSDJWT", "req", req)

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

	// Build credential options
	opts := &sdjwtvc.CredentialOptions{}

	// Call registry to allocate a status list entry for revocation support
	if c.registryClient == nil {
		return nil, fmt.Errorf("registry client not configured")
	}

	grpcReply, err := c.registryClient.TokenStatusListAddStatus(ctx, &apiv1_registry.TokenStatusListAddStatusRequest{
		Status: 0, // VALID status for new credential
	})
	if err != nil {
		c.log.Error(err, "failed to get status list entry from registry")
		return nil, fmt.Errorf("failed to allocate status list entry: %w", err)
	}

	// Construct status URI based on registry endpoint and section
	statusURI := fmt.Sprintf("%s/statuslists/%d", c.cfg.Registry.ExternalServerURL, grpcReply.GetSection())
	opts.TokenStatusList = &sdjwtvc.TokenStatusListReference{
		Index: grpcReply.GetIndex(),
		URI:   statusURI,
	}
	c.log.Debug("status list entry allocated", "section", grpcReply.GetSection(), "index", grpcReply.GetIndex(), "uri", statusURI)

	// Build SD-JWT using sdjwtvc package with the signer interface
	sdClient := sdjwtvc.New()
	token, err := sdClient.BuildCredentialWithSigner(
		ctx,
		c.cfg.Issuer.JWTAttribute.Issuer,
		c.signer,
		credentialConstructor.VCT,
		req.DocumentData,
		req.JWK,
		vctm,
		opts,
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
		TokenStatusListSection: grpcReply.GetSection(),
		TokenStatusListIndex:   grpcReply.GetIndex(),
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
