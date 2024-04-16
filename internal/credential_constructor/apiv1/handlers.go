package apiv1

import (
	"context"
	"vc/pkg/model"

	"github.com/masv3971/gosdjwt"
)

// SDJWTRequest holds the request
type SDJWTRequest struct {
	Meta *model.MetaData `json:"meta"`
}

// SDJWTReply is the reply
type SDJWTReply struct {
	Upload *model.Upload `json:"upload"`
}

// SDJWT gets a credential
func (c *Client) SDJWT(ctx context.Context, req *SDJWTRequest) (*SDJWTReply, error) {
	mockUpload := &model.Upload{
		Meta: req.Meta,
	}

	//switch req.Meta.DocumentType {
	//case "PDA1":
	//	mockUpload.DocumentData = c.PDA1.random(ctx)
	//case "EHIC":
	//	mockUpload.DocumentData = c.EHIC.random(ctx)
	//default:
	//	return nil, model.ErrNoKnownDocumentType
	//}

	reply := &SDJWTReply{
		Upload: mockUpload,
	}

	return reply, nil
}

type CredentialRequest struct{}

type CredentialReply struct {
	Token *gosdjwt.SDJWT
}

// Credential gets a credential
func (c *Client) Credential(ctx context.Context, req *CredentialRequest) (*CredentialReply, error) {
	token, err := c.EHIC.randomV2(ctx)
	if err != nil {
		return nil, err
	}
	return &CredentialReply{
		Token: token,
	}, nil
}
