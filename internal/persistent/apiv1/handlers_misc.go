package apiv1

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
)

// Status return status for each ladok instance
func (c *Client) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	_, span := c.tracer.Start(ctx, "apiv1:Status")
	defer span.End()

	probes := model.Probes{}

	status := probes.Check("persistent")

	return status, nil
}
