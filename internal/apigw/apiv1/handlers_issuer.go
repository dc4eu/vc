package apiv1

import (
	"context"
	"encoding/json"
	apiv1_issuer "vc/internal/gen/issuer/apiv1.issuer"
	apiv1_registry "vc/internal/gen/registry/apiv1.registry"
	"vc/pkg/helpers"
	"vc/pkg/model"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// CredentialRequest is the request for Credential
type CredentialRequest struct {
	AuthenticSource         string `json:"authentic_source" binding:"required"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id" binding:"required"`
	CredentialType          string `json:"credential_type" binding:"required"`
	DocumentID              string `json:"document_id" binding:"required"`
	DocumentType            string `json:"document_type" binding:"required"`
	DocumentVersion         string `json:"document_version" bind:"required"`
	CollectID               string `json:"collect_id" binding:"required"`
	DateOfBirth             string `json:"date_of_birth" binding:"required"`
	LastName                string `json:"last_name" binding:"required"`
	FirstName               string `json:"first_name" binding:"required"`
}

// CredentialReply is the reply for Credential
type CredentialReply struct {
	SDJWT string `json:"sdjwt"`
}

// Credential makes a credential based on
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
//
// Credential is the credential endpoint
func (c *Client) Credential(ctx context.Context, req *CredentialRequest) (*apiv1_issuer.MakeSDJWTReply, error) {
	c.log.Info("Credential", "req", req)
	// IDMapping

	// GetDocument
	uploadDoc, err := c.db.VCDatastoreColl.GetDocument(ctx, &model.MetaData{
		AuthenticSource:         req.AuthenticSource,
		AuthenticSourcePersonID: req.AuthenticSourcePersonID,
		DocumentVersion:         req.DocumentVersion,
		DocumentType:            req.DocumentType,
		DocumentID:              req.DocumentID,
		FirstName:               req.FirstName,
		LastName:                req.LastName,
		DateOfBirth:             req.DateOfBirth,
	})
	if err != nil {
		return nil, err
	}
	if uploadDoc == nil {
		return nil, helpers.ErrNoDocumentFound
	}
	if uploadDoc.DocumentData == nil {
		return nil, helpers.ErrNoDocumentData
	}

	documentData, err := json.Marshal(uploadDoc.DocumentData)
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
		AuthenticSource:         req.AuthenticSource,
		AuthenticSourcePersonID: req.AuthenticSourcePersonID,
		DocumentType:            req.DocumentType,
		DocumentID:              req.DocumentID,
		DocumentVersion:         req.DocumentVersion,
		CollectID:               req.CollectID,
		DateOfBirth:             req.DateOfBirth,
		LastName:                req.LastName,
		FirstName:               req.FirstName,
		CredentialType:          req.CredentialType,
		DocumentData:            documentData,
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

	reply := &RevokeReply{
		Data: struct {
			Status bool `json:"status"`
		}{
			Status: resp.Status,
		},
	}
	return reply, nil
}
