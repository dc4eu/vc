package httpserver

import (
	"context"
	apiv1_registry "vc/internal/gen/registry/apiv1.registry"
	"vc/pkg/model"
)

// Apiv1 interface
type Apiv1 interface {
	Add(ctx context.Context, req *apiv1_registry.AddRequest) (*apiv1_registry.AddReply, error)
	Revoke(ctx context.Context, req *apiv1_registry.RevokeRequest) (*apiv1_registry.RevokeReply, error)
	Validate(ctx context.Context, req *apiv1_registry.ValidateRequest) (*apiv1_registry.ValidateReply, error)

	Status(ctx context.Context) (*model.Health, error)
}
