package apiv1

import (
	"context"
	"encoding/json"
	apiv1_registry "vc/internal/gen/registry/apiv1.registry"
	"vc/pkg/ehic"
	"vc/pkg/helpers"
	"vc/pkg/pda1"

	"github.com/masv3971/gosdjwt"

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
	AuthenticSource         string `json:"authentic_source" validate:"required"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id" validate:"required"`
	DocumentID              string `json:"document_id" validate:"required"`
	DocumentType            string `json:"document_type" validate:"required"`
	DocumentVersion         string `json:"document_version" validate:"required"`
	CollectID               string `json:"collect_id" validate:"required"`
	DateOfBirth             string `json:"date_of_birth" validate:"required"`
	LastName                string `json:"last_name" validate:"required"`
	FirstName               string `json:"first_name" validate:"required"`
	CredentialType          string `json:"credential_type" validate:"required"`
	DocumentData            []byte `json:"document_data" validate:"required"`
}

// CreateCredentialReply is the reply for Credential
type CreateCredentialReply struct {
	Data *gosdjwt.PresentationFlat `json:"data"`
}

// CreateCredential creates a credential
func (c *Client) MakeSDJWT(ctx context.Context, req *CreateCredentialRequest) (*CreateCredentialReply, error) {
	ctx, span := c.tp.Start(ctx, "apiv1:CreateCredential")
	defer span.End()

	if err := helpers.Check(ctx, c.cfg, req, c.log); err != nil {
		c.log.Debug("Validation", "err", err)
		return nil, err
	}

	// Build SDJWT
	var sdjwt *gosdjwt.SDJWT
	switch req.DocumentType {
	case "PDA1":
		doc := &pda1.Document{}
		if err := json.Unmarshal(req.DocumentData, &doc); err != nil {
			return nil, err
		}
		var err error
		sdjwt, err = c.pda1Client.sdjwt(ctx, doc)
		if err != nil {
			return nil, err
		}

		c.auditLog.AddAuditLog(ctx, "create_credential", sdjwt.PresentationFlat())

	case "EHIC":
		doc := &ehic.Document{}
		if err := json.Unmarshal(req.DocumentData, &doc); err != nil {
			return nil, err
		}
		var err error
		sdjwt, err = c.ehicClient.sdjwt(ctx, doc)
		if err != nil {
			return nil, err
		}

		c.auditLog.AddAuditLog(ctx, "create_credential", sdjwt.PresentationFlat())
	}
	reply := &CreateCredentialReply{
		Data: sdjwt.PresentationFlat(),
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
	ctx, span := c.tp.Start(ctx, "apiv1:Revoke")
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
