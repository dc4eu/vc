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
	ctx, span := c.tracer.Start(ctx, "apiv1:MockNext")
	defer span.End()

	mockUpload, err := c.mockOne(ctx, inData.MockInputData)
	if err != nil {
		return nil, err
	}

	resp, err := c.uploader(ctx, mockUpload)
	if err != nil {
		c.log.Error(err, "failed to upload", "mockUpload", mockUpload)
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New("upload failed")
	}

	reply := &MockNextReply{
		Upload: mockUpload,
	}

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
	ctx, span := c.tracer.Start(ctx, "apiv1:MockBulk")
	defer span.End()

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

// Health returns the status of the service
func (c *Client) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	_, span := c.tracer.Start(ctx, "apiv1:Health")
	defer span.End()

	probes := model.Probes{}
	status := probes.Check("mockas")
	return status, nil
}
