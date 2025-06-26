package apiv1

import "context"

type VerificationRequestObjectRequest struct {
	ID string `form:"id" uri:"id"`
}

type VerificationRequestObjectResponse struct{}

func (c *Client) VerificationRequestObject(ctx context.Context, req *VerificationRequestObjectRequest) (*VerificationRequestObjectResponse, error) {
	c.log.Debug("Verification request object", "req", req)

	return nil, nil
}

type VerificationDirectPostRequest struct {
}

type VerificationDirectPostResponse struct{}

func (c *Client) VerificationDirectPost(ctx context.Context, req *VerificationDirectPostRequest) (*VerificationDirectPostResponse, error) {
	c.log.Debug("Verification direct-post", "req", req)

	return nil, nil
}
