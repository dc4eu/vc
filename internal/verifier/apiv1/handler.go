package apiv1

import (
	"context"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/pkg/model"
)

// Status return status for each ladok instance
func (c *Client) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	probes := model.Probes{}

	//for _, ladok := range c.ladokInstances {
	//	redis := ladok.Atom.StatusRedis(ctx)
	//	ladok := ladok.Rest.StatusLadok(ctx)

	//	manyStatus = append(manyStatus, redis)
	//	manyStatus = append(manyStatus, ladok)
	//}
	status := probes.Check("verifier")

	return status, nil
}
