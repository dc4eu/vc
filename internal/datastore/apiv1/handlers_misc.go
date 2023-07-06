package apiv1

import (
	"context"
	"vc/pkg/model"
)

// Status return status for each ladok instance
func (c *Client) Status(ctx context.Context) (*model.Health, error) {
	probes := model.Probes{}

	//for _, ladok := range c.ladokInstances {
	//	redis := ladok.Atom.StatusRedis(ctx)
	//	ladok := ladok.Rest.StatusLadok(ctx)

	//	manyStatus = append(manyStatus, redis)
	//	manyStatus = append(manyStatus, ladok)
	//}
	status := probes.Check("datastore")

	return status, nil
}
