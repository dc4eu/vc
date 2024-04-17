package apiv1

import (
	"context"
	"errors"
	"vc/pkg/model"
)

// MockNextRequest holds the request
type MockNextRequest struct {
	DocumentType            string `json:"document_type"`
	AuthenticSource         string `json:"authentic_source"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
}

// MockNextReply is the reply
type MockNextReply struct {
	Upload *model.Upload `json:"upload"`
}

// MockNext sends one mock upload to the datastore
func (c *Client) MockNext(ctx context.Context, inData *MockNextRequest) (*MockNextReply, error) {
	// send to datastore
	c.log.Debug("mocknext")
	mockUpload, err := c.mockOne(ctx, inData.AuthenticSourcePersonID, inData.AuthenticSource, inData.DocumentType)
	if err != nil {
		return nil, err
	}

	resp, err := c.uploader(ctx, mockUpload)
	if err != nil {
		return nil, err
	}
	c.log.Debug("after uploader")
	c.log.Debug("mocknext", "remote status code", resp.StatusCode)
	c.log.Debug("mocknext", "resp body", resp.Body)

	if resp.StatusCode != 200 {
		return nil, errors.New("upload failed")
	}
	c.log.Debug("mocknext", "remote status code", resp.StatusCode)

	reply := &MockNextReply{
		Upload: mockUpload,
	}

	c.log.Debug("mocknext", "reply", reply)

	c.log.Debug("mocknext", "status", "finished")

	return reply, nil
}

// MockBulkRequest holds the request
type MockBulkRequest struct {
	DocumentType            string `json:"document_type"`
	AuthenticSource         string `json:"authentic_source"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
	N                       int    `form:"n"`
}

// MockBulkReply is the reply
type MockBulkReply struct {
	DocumentIDS []string `json:"document_ids"`
}

// MockBulk sends N mock uploads to the datastore
func (c *Client) MockBulk(ctx context.Context, inData *MockBulkRequest) (*MockBulkReply, error) {
	documentIDS := []string{}

	if inData.N < 1 {
		return nil, errors.New("n must be greater than 0")
	}

	for i := 0; i < inData.N; i++ {
		mockUpload, err := c.mockOne(ctx, inData.AuthenticSourcePersonID, inData.AuthenticSource, inData.DocumentType)
		if err != nil {
			return nil, err
		}
		documentIDS = append(documentIDS, mockUpload.Meta.DocumentID)

		resp, err := c.uploader(ctx, mockUpload)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != 200 {
			return nil, errors.New("upload failed")
		}
	}

	return &MockBulkReply{
		DocumentIDS: documentIDS,
	}, nil
}
