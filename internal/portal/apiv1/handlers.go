package apiv1

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
)

// Status return status for each ladok instance
func (c *Client) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	probes := model.Probes{}

	status := probes.Check("registry")

	return status, nil
}
