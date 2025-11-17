package apiv1

import (
	"context"
	"errors"
	"vc/internal/gen/status/apiv1_status"
)

var (
	ErrInvalidClient        = errors.New("invalid client")
	ErrInvalidGrant         = errors.New("invalid grant")
	ErrInvalidRequest       = errors.New("invalid request")
	ErrInvalidScope         = errors.New("invalid scope")
	ErrUnauthorizedClient   = errors.New("unauthorized client")
	ErrUnsupportedGrantType = errors.New("unsupported grant type")
	ErrAccessDenied         = errors.New("access denied")
	ErrServerError          = errors.New("server error")
	ErrSessionNotFound      = errors.New("session not found")
	ErrSessionExpired       = errors.New("session expired")
	ErrInvalidVP            = errors.New("invalid verifiable presentation")
)

// Health returns the health status
func (c *Client) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	return &apiv1_status.StatusReply{
		Data: &apiv1_status.StatusReply_Data{
			ServiceName: "verifier-proxy",
			Status:      "healthy",
			BuildVariables: &apiv1_status.BuildVariables{
				Version: "0.1.0",
			},
		},
	}, nil
}
