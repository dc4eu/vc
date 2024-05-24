package grpcserver

import (
	"context"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/internal/issuer/apiv1"
)

// Apiv1 interface
type Apiv1 interface {
	MakeSDJWT(ctx context.Context, req *apiv1.CreateCredentialRequest) (*apiv1.CreateCredentialReply, error)

	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
