package apiv1

import (
	"context"
	"time"
	"vc/internal/datastore/db"
	"vc/pkg/helpers"
	"vc/pkg/model"
	"vc/pkg/pda1"

	"github.com/google/uuid"
)

// PDA1UploadRequest is the request for PDA1Upload
type PDA1UploadRequest struct {
	Data *db.PDA1Upload `json:"data"`
}

// PDA1UploadReply is the reply for PDA1Upload
type PDA1UploadReply struct {
	UploadID string `json:"upload_id"`
}

// PDA1Upload uploads PDA1 data
func (c *Client) PDA1Upload(ctx context.Context, req *PDA1UploadRequest) (*PDA1UploadReply, error) {
	uploadID := uuid.NewString()

	req.Data.Meta = &model.Meta{
		UploadID:     uploadID,
		Timestamp:    time.Now(),
		DocumentType: "PDA1",
	}

	if err := helpers.Check(req.Data, c.logger.New("validate_PDA1Upload")); err != nil {
		return nil, err
	}
	if err := c.db.PDA1Coll.Save(ctx, req.Data); err != nil {
		return nil, err
	}
	reply := &PDA1UploadReply{
		UploadID: uploadID,
	}
	return reply, nil
}

// PDA1IDRequest is the request for PDA1ID
type PDA1IDRequest struct {
	UploadID string `uri:"upload_id"`
}

// PDA1ID is the request for PDA1ID
func (c *Client) PDA1ID(ctx context.Context, req *PDA1IDRequest) (*db.PDA1Upload, error) {
	if err := helpers.Check(req, c.logger.New("validate_PDA1ID")); err != nil {
		return nil, err
	}
	doc, err := c.db.PDA1Coll.GetID(ctx, req.UploadID)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

// PDA1SearchRequest is the request for PDA1Search
type PDA1SearchRequest struct {
	Data *db.PDA1SearchAttributes `json:"data"`
}

// PDA1Search searches PDA1 data and return one result, if any
func (c *Client) PDA1Search(ctx context.Context, req *PDA1SearchRequest) (*pda1.Document, error) {
	res, err := c.db.PDA1Coll.Search(ctx, req.Data)
	if err != nil {
		return nil, err
	}
	return res, nil
}
