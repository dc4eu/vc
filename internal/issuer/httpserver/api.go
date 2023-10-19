package httpserver

import (
	"context"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/internal/issuer/apiv1"
)

// Apiv1 interface
type Apiv1 interface {
	PDFSign(ctx context.Context, req *apiv1.PDFSignRequest) (*apiv1.PDFSignReply, error)
	PDFValidate(ctx context.Context, req *apiv1.PDFValidateRequest) (*apiv1.PDFValidateReply, error)
	PDFGetSigned(ctx context.Context, req *apiv1.PDFGetSignedRequest) (*apiv1.PDFGetSignedReply, error)
	PDFRevoke(ctx context.Context, req *apiv1.PDFRevokeRequest) (*apiv1.PDFRevokeReply, error)

	Get(ctx context.Context, indata *apiv1.GetRequest) (*apiv1.GetReply, error)

	Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
