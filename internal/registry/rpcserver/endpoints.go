package rpcserver

import (
	"context"

	apiv1_registry "vc/internal/gen/registry/apiv1.registry"
	apiv1_status "vc/internal/gen/status/apiv1.status"
)

// Add adds an entity to the registry
func (s *Service) Add(ctx context.Context, req *apiv1_registry.AddRequest) (*apiv1_registry.AddReply, error) {
	return s.apiv1.Add(ctx, req)
}

// Revoke revokes an entity from the registry
func (s *Service) Revoke(ctx context.Context, reg *apiv1_registry.RevokeRequest) (*apiv1_registry.RevokeReply, error) {
	return s.apiv1.Revoke(ctx, reg)
}

// Validate validates an entity in the registry
func (s *Service) Validate(ctx context.Context, req *apiv1_registry.ValidateRequest) (*apiv1_registry.ValidateReply, error) {
	return s.apiv1.Validate(ctx, req)
}

func (s *Service) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	return s.apiv1.Status(ctx, req)
}
