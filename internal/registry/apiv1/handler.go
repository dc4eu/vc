package apiv1

import (
	"context"
	"vc/pkg/helpers"
	"vc/pkg/model"
)

// AddRequest is the request to add a registry
type AddRequest struct {
	Entity string `json:"entity" validate:"required"`
}

// AddReply is the reply for registry
type AddReply struct {
}

// Add adds a new entity into the registry
func (c *Client) Add(ctx context.Context, req *AddRequest) (*AddReply, error) {
	if err := helpers.Check(req, c.logger); err != nil {
		return nil, err
	}

	if err := c.tree.Insert(req.Entity); err != nil {
		return nil, err
	}

	return nil, nil
}

// RevokeRequest is the request for verify pdf
type RevokeRequest struct {
	Entity string `json:"entity" validate:"required"`

}

// RevokeReply is the reply for verify pdf
type RevokeReply struct {
}

// Revoke revokes an entity in the registry
func (c *Client) Revoke(ctx context.Context, req *RevokeRequest) (*RevokeReply, error) {
	if err := c.tree.Remove(req.Entity); err != nil {
		return nil, err
	}

	return nil, nil
}

// ValidateRequest validates an entity in the registry
type ValidateRequest struct {
	Entity string `json:"entity" validate:"required"`
}

// ValidateReply is the reply for registry
type ValidateReply struct {
	Valid bool `json:"valid"`
}

// Validate validates an entity in the registry
func (c *Client) Validate(ctx context.Context, req *ValidateRequest) (*ValidateReply, error) {
	valid, err := c.tree.Validate(req.Entity)
	if err != nil {
		return nil, err
	}

	return &ValidateReply{Valid: valid}, nil
}

// Status return status for each ladok instance
func (c *Client) Status(ctx context.Context) (*model.Health, error) {
	probes := model.Probes{}
	//probes = append(probes, c.kv.Status(ctx))

	status := probes.Check("registry")

	return status, nil
}
