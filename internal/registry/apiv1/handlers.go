package apiv1

import (
	"context"
	"vc/internal/gen/registry/apiv1_registry"
	"vc/internal/gen/status/apiv1_status"

	// swagger complains if this is not imported
	_ "vc/pkg/helpers"
	"vc/pkg/model"
)

// Add adds a new entity into the registry
func (c *Client) Add(ctx context.Context, req *apiv1_registry.AddRequest) (*apiv1_registry.AddReply, error) {
	if err := c.tree.Insert(req.Entity); err != nil {
		return nil, err
	}
	c.log.Info("Hash added")

	return nil, nil
}

// Revoke revokes an entity in the registry
func (c *Client) Revoke(ctx context.Context, req *apiv1_registry.RevokeRequest) (*apiv1_registry.RevokeReply, error) {
	if err := c.tree.Remove(req.Entity); err != nil {
		return nil, err
	}
	c.log.Info("Hash revoked")

	return nil, nil
}

// ValidateReply is the reply for registry
type ValidateReply struct {
	Data *apiv1_registry.ValidateReply `json:"data"`
}

// Validate validates an entity in the registry
//
//	@Summary		Validate entity
//	@ID				registry-validate
//	@Description	validates an entity in the registry
//	@Tags			registry
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	ValidateReply					"Success"
//	@Failure		400	{object}	helpers.ErrorResponse			"Bad Request"
//	@Param			req	body		apiv1_registry.ValidateRequest	true	" "
//	@Router			/ladok/pdf/sign [post]
func (c *Client) Validate(ctx context.Context, req *apiv1_registry.ValidateRequest) (*ValidateReply, error) {
	valid, err := c.tree.Validate(req.Entity)
	if err != nil {
		return nil, err
	}
	reply := &ValidateReply{
		Data: &apiv1_registry.ValidateReply{
			Valid: valid,
		},
	}

	return reply, nil
}

// Status return status for each ladok instance
func (c *Client) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	probes := model.Probes{}

	status := probes.Check("registry")

	return status, nil
}
