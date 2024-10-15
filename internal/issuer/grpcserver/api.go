package grpcserver

import (
	"context"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/gen/status/apiv1_status"
	"vc/internal/issuer/apiv1"
)

// Apiv1 interface
type Apiv1 interface {
	MakeSDJWT(ctx context.Context, req *apiv1.CreateCredentialRequest) (*apiv1.CreateCredentialReply, error)
	JWKS(ctx context.Context, req *apiv1_issuer.Empty) (*apiv1_issuer.JwksReply, error)

	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
