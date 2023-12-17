package apiv1

import (
	"context"
	"vc/pkg/model"
)

// MockNextRequest holds the request
type MockNextRequest struct {
	Meta *model.MetaData `json:"meta"`
}

// MockNextReply is the reply
type MockNextReply struct {
	Upload *model.Upload `json:"upload"`
}

// MockNext gets a credential
func (c *Client) MockNext(ctx context.Context, indata *MockNextRequest) (*MockNextReply, error) {
	mockUpload := &model.Upload{
		Meta: *indata.Meta,
	}

	switch indata.Meta.DocumentType {
	case "PDA1":
		mockUpload.DocumentData = c.PDA1.random(ctx)
	case "EHIC":
		mockUpload.DocumentData = c.EHIC.random(ctx)
	default:
		return nil, model.ErrNoKnownDocumentType
	}

	reply := &MockNextReply{
		Upload: mockUpload,
	}

	return reply, nil
}
