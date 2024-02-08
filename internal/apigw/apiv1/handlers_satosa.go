package apiv1

import "context"

// SatosaCredentialRequest is the request for SatosaAuthz
type SatosaCredentialRequest struct {
	AuthenticSource string `form:"authentic_source" binding:"required"`
	DocumentID      string `form:"document_id" binding:"required"`
	DocumentType    string `form:"document_type" binding:"required"`
	CollectID       string `form:"collect_id" binding:"required"`
	DateOfBirth     string `form:"date_of_birth" binding:"required"`
	LastName        string `form:"last_name" binding:"required"`
	FirstName       string `form:"first_name" binding:"required"`
	UID             string `form:"uid" binding:"required"`
}

// SatosaCredentialReply is the reply for SatosaAuthz
type SatosaCredentialReply struct {
	SDJWT string `json:"sdjwt"`
}

// SatosaCredential is the credential endpoint for SATOSA
func (c *Client) SatosaCredential(ctx context.Context, req *SatosaCredentialRequest) (*SatosaCredentialReply, error) {
	reqCredential := &CredentialRequest{
		AuthenticSource: req.AuthenticSource,
		DocumentID:      req.DocumentID,
		DocumentType:    req.DocumentType,
		CollectID:       req.CollectID,
		DateOfBirth:     req.DateOfBirth,
		LastName:        req.LastName,
		FirstName:       req.FirstName,
		UID:             req.UID,
	}

	reply, err := c.Credential(ctx, reqCredential)
	if err != nil {
		return nil, err
	}

	return &SatosaCredentialReply{SDJWT: reply.SDJWT}, nil
}
