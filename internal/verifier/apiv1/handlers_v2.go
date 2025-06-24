package apiv1

import (
	"context"
)

type VerificationRequest struct {
	ID string `json:"id" form:"id" uri:"id"`
}

type VerificationResponse struct{}

func (c *Client) Verification(ctx context.Context, req *VerificationRequest) (*VerificationResponse, error) {
	c.log.Debug("Verification", "req", req)

	return nil, nil
}
