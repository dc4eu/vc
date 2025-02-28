package httpserver

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/internal/verifier/apiv1"
	"vc/pkg/openid4vp"
)

type Apiv1 interface {

	// openid4vp
	QRCode(ctx context.Context, request *openid4vp.DocumentTypeEnvelope) (*openid4vp.QR, error)

	// misc
	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)

	// deprecated
	VerifyCredential(ctx context.Context, request *apiv1.Credential) (*apiv1.VerifyCredentialReply, error)
	DecodeCredential(ctx context.Context, request *apiv1.Credential) (*apiv1.DecodedCredential, error)
}
