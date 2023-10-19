package httpserver

import (
	"context"
	apiv1_registry "vc/internal/gen/registry/apiv1.registry"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/internal/registry/apiv1"
)

// Apiv1 interface
type Apiv1 interface {
	Validate(ctx context.Context, req *apiv1_registry.ValidateRequest) (*apiv1.ValidateReply, error)

	Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
