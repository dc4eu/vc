package httpserver

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/internal/verifier/apiv1"
	"vc/pkg/oauth2"
)

type Apiv1 interface {
	// oauth2
	OAuthMetadata(ctx context.Context) (*oauth2.AuthorizationServerMetadata, error)

	// misc
	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)

	// Verification
	VerificationRequestObject(ctx context.Context, req *apiv1.VerificationRequestObjectRequest) (string, error)

	// UI
	UIInteraction(ctx context.Context, req *apiv1.UIInteractionRequest) (*apiv1.UIInteractionReply, error)
	UIMetadata(ctx context.Context) (*apiv1.UIMetadataReply, error)
}
