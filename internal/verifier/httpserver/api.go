package httpserver

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/internal/verifier/apiv1"
	"vc/pkg/openid4vp"
)

type Apiv1 interface {

	// openid4vp
	GenerateQRCode(ctx context.Context, request *openid4vp.DocumentTypeEnvelope) (*openid4vp.QR, error)
	GetAuthorizationRequest(ctx context.Context, sessionID string) (*openid4vp.AuthorizationRequest, error)
	Callback(ctx context.Context, sessionID string, callbackID string, request *openid4vp.AuthorizationResponse) (*openid4vp.CallbackReply, error)

	// openid4vp-web
	GetVerificationResult(ctx context.Context, sessionID string) (*openid4vp.VerificationResult, error)

	//ui-web dev support
	GetVPFlowDebugInfo(ctx context.Context, request *apiv1.VPFlowDebugInfoRequest) (*apiv1.VPFlowDebugInfoReply, error)
	SaveRequestDataToVPSession(ctx context.Context, sessionID string, callbackID string, request *openid4vp.JsonRequestData) error

	// misc
	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)

	// deprecated
	VerifyCredential(ctx context.Context, request *apiv1.Credential) (*apiv1.VerifyCredentialReply, error)
	DecodeCredential(ctx context.Context, request *apiv1.Credential) (*apiv1.DecodedCredential, error)
}
