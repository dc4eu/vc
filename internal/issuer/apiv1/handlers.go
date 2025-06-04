package apiv1

import (
	"context"
	"encoding/json"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/gen/registry/apiv1_registry"
	"vc/pkg/education"
	"vc/pkg/helpers"
	"vc/pkg/model"
	"vc/pkg/socialsecurity"

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
	DocumentType string            `json:"document_type" validate:"required"`
	DocumentData []byte            `json:"document_data" validate:"required"`
	JWK          *apiv1_issuer.Jwk `json:"jwk" validate:"required"`
}

// CreateCredentialReply is the reply for Credential
type CreateCredentialReply struct {
	//Data *sdjwt.PresentationFlat `json:"data"`
	Data []*apiv1_issuer.Credential `json:"data"`
}

// MakeSDJWT creates a credential
func (c *Client) MakeSDJWT(ctx context.Context, req *CreateCredentialRequest) (*CreateCredentialReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:CreateCredential")
	defer span.End()

	c.log.Debug("create credential", "document_type", req.DocumentType)

	if err := helpers.Check(ctx, c.cfg, req, c.log); err != nil {
		c.log.Debug("Validation", "err", err)
		return nil, err
	}

	// Build SDJWT
	var token string
	var err error
	switch req.DocumentType {
	case model.CredentialTypeUrnEudiPda11:
		doc := &socialsecurity.PDA1Document{}
		if err := json.Unmarshal(req.DocumentData, &doc); err != nil {
			return nil, err
		}
		token, err = c.pda1Client.sdjwt(ctx, doc, req.JWK, nil)
		if err != nil {
			c.log.Error(err, "failed to create sdjwt", "document_type", req.DocumentType)
			return nil, err
		}

	case model.CredentialTypeUrnEudiEhic1:
		doc := &socialsecurity.EHICDocument{}
		if err := json.Unmarshal(req.DocumentData, &doc); err != nil {
			return nil, err
		}
		token, err = c.ehicClient.sdjwt(ctx, doc, req.JWK, nil)
		if err != nil {
			c.log.Error(err, "failed to create sdjwt", "document_type", req.DocumentType)
			return nil, err
		}

	case model.CredentialTypeUrnEduiElm1:
		doc := &education.ELMDocument{}
		if err := json.Unmarshal(req.DocumentData, &doc); err != nil {
			return nil, err
		}
		token, err = c.elmClient.sdjwt(ctx, doc, req.JWK, nil)
		if err != nil {
			c.log.Error(err, "failed to create sdjwt", "document_type", req.DocumentType)
			return nil, err
		}

	case model.CredentialTypeUrnEduiDiploma1:
		doc := map[string]any{}
		if err := json.Unmarshal(req.DocumentData, &doc); err != nil {
			return nil, err
		}
		token, err = c.diplomaClient.sdjwt(ctx, doc, req.JWK, nil)
		if err != nil {
			c.log.Error(err, "failed to create sdjwt", "document_type", req.DocumentType)
			return nil, err
		}

	case model.CredentialTypeUrnEduiMicroCredential1:
		doc := map[string]any{}
		if err := json.Unmarshal(req.DocumentData, &doc); err != nil {
			return nil, err
		}
		token, err = c.microCredentialClient.sdjwt(ctx, doc, req.JWK, nil)
		if err != nil {
			c.log.Error(err, "failed to create sdjwt", "document_type", req.DocumentType)
			return nil, err
		}

	case "open_badge":
		doc := &education.OpenbadgeCompleteDocument{}
		if err := json.Unmarshal(req.DocumentData, &doc); err != nil {
			return nil, err
		}
		token, err = c.openBadgeCompleteClient.sdjwt(ctx, doc, req.JWK, nil)
		if err != nil {
			c.log.Error(err, "failed to create sdjwt", "document_type", req.DocumentType)
			return nil, err
		}

	case model.CredentialTypeUrnEudiPid1:
		doc := &model.Identity{}
		if err := json.Unmarshal(req.DocumentData, &doc); err != nil {
			return nil, err
		}
		token, err = c.pidClient.sdjwt(ctx, doc, req.JWK, nil)
		if err != nil {
			c.log.Error(err, "failed to create sdjwt", "document_type", req.DocumentType)
			return nil, err
		}
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
	ctx, span := c.tracer.Start(ctx, "apiv1:Revoke")
	defer span.End()

	optInsecure := grpc.WithTransportCredentials(insecure.NewCredentials())

	conn, err := grpc.Dial(c.cfg.Registry.GRPCServer.Addr, optInsecure)
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
