package apiv1

import (
	"context"
	"time"
	"vc/internal/datastore/db"
	"vc/pkg/helpers"
	"vc/pkg/model"

	"github.com/google/uuid"
)

// LadokUploadRequest is the request for LadokUpload
type LadokUploadRequest struct {
	Data *db.LadokUpload `json:"data"`
}

// LadokUploadReply is the reply for LadokUpload
type LadokUploadReply struct {
	UploadID string `json:"upload_id"`
}

// LadokUpload uploads Ladok data
func (c *Client) LadokUpload(ctx context.Context, req *LadokUploadRequest) (*LadokUploadReply, error) {
	uploadID := uuid.NewString()

	req.Data.Meta = &model.Meta{
		UploadID:     uploadID,
		Timestamp:    time.Now(),
		DocumentType: "ladok",
	}

	if err := helpers.Check(req.Data, c.logger.New("validate_LadokUpload")); err != nil {
		return nil, err
	}
	if err := c.db.LadokColl.Save(ctx, req.Data); err != nil {
		return nil, err
	}
	reply := &LadokUploadReply{
		UploadID: uploadID,
	}
	return reply, nil
}

// LadokIDRequest is the request for LadokID
type LadokIDRequest struct {
	UploadID string `uri:"upload_id"`
}

// LadokID is the request for LadokID
func (c *Client) LadokID(ctx context.Context, req *LadokIDRequest) (*db.LadokUpload, error) {
	if err := helpers.Check(req, c.logger.New("validate_LadokID")); err != nil {
		return nil, err
	}
	doc, err := c.db.LadokColl.GetID(ctx, req.UploadID)
	if err != nil {
		return nil, err
	}
	return doc, nil
}
