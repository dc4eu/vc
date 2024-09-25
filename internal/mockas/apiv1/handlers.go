package apiv1

import (
	"context"
	"errors"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
)

// MockNextRequest holds the request
type MockNextRequest struct {
	MockInputData
}

// MockNextReply is the reply
type MockNextReply struct {
	Upload *uploadMock `json:"upload"`
}

// MockNext sends one mock upload to the datastore
func (c *Client) MockNext(ctx context.Context, inData *MockNextRequest) (*MockNextReply, error) {
	c.log.Debug("mocknext")
	mockUpload, err := c.mockOne(ctx, inData.MockInputData)
	if err != nil {
		return nil, err
	}
	c.log.Debug("mocknext", "mockUpload", mockUpload)

	resp, err := c.uploader(ctx, mockUpload)
	if err != nil {
		//TODO ta bort nedan error logging?
		c.log.Error(err, "failed to upload", "mockUpload", mockUpload)
		return nil, err
	}

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
	MockInputData
	N int `form:"n"`
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
		mockUpload, err := c.mockOne(ctx, inData.MockInputData)
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

func (c *Client) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	probes := model.Probes{}
	status := probes.Check("mockas")
	return status, nil
}
