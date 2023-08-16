package apiv1

import (
	"context"
	"time"
	"vc/internal/datastore/db"
	"vc/pkg/helpers"
	"vc/pkg/model"

	"github.com/google/uuid"
)

// EHICUploadRequest is the request for EHICUpload
type EHICUploadRequest struct {
	Data *db.EHICUpload `json:"data"`
}

// EHICUploadReply is the reply for EHICUpload
type EHICUploadReply struct {
	UploadID string `json:"upload_id"`
}

// EHICUpload uploads EHIC data
func (c *Client) EHICUpload(ctx context.Context, req *EHICUploadRequest) (*EHICUploadReply, error) {
	uploadID := uuid.NewString()

	req.Data.Meta = &model.Meta{
		UploadID:     uploadID,
		Timestamp:    time.Now(),
		DocumentType: "ehic",
	}

	if err := helpers.Check(req.Data, c.logger.New("validate_EHICUpload")); err != nil {
		return nil, err
	}
	if err := c.db.EHICColl.Save(ctx, req.Data); err != nil {
		return nil, err
	}
	reply := &EHICUploadReply{
		UploadID: uploadID,
	}
	return reply, nil
}

// EHICIDRequest is the request for EHICID
type EHICIDRequest struct {
	UploadID string `uri:"upload_id" validate:"required"`
}

// EHICIDReply is the reply for EHICID
type EHICIDReply struct {
	db.PDA1Upload
}

// EHICID is the request for EHICID
func (c *Client) EHICID(ctx context.Context, req *EHICIDRequest) (*db.EHICUpload, error) {
	if err := helpers.Check(req, c.logger.New("validate_EHICID")); err != nil {
		return nil, err
	}
	return c.db.EHICColl.GetID(ctx, req.UploadID)
}
