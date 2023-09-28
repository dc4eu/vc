package rpcserver

import (
	"context"

	apiv1_registry "vc/internal/gen/registry/apiv1.registry"
)

// Add adds an entity to the registry
func (s *Service) Add(ctx context.Context, req *apiv1_registry.AddRequest) (*apiv1_registry.AddReply, error) {
	return s.apiv1.Add(ctx, req)
}
