package apiv1

import (
	"context"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/pkg/model"
)

// Health return health for this service and dependencies
func (c *Client) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	c.log.Info("health handler")
	probes := model.Probes{}
	probes = append(probes, c.kv.Status(ctx))
	probes = append(probes, c.db.Status(ctx))

	status := probes.Check("issuer")

	return status, nil
}
