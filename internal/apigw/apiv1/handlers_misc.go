package apiv1

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
)

// Health return health for this service and dependencies
func (c *Client) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:Health")
	defer span.End()

	probes := model.Probes{}
	probes = append(probes, c.db.Status(ctx))

	status := probes.Check("apigw")

	return status, nil
}
