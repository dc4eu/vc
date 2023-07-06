package httpserver

import (
	"context"
	"vc/internal/issuer/apiv1"
	"vc/pkg/model"
)

// Apiv1 interface
type Apiv1 interface {
	PDFSign(ctx context.Context, req *apiv1.PDFSignRequest) (*apiv1.PDFSignReply, error)
	PDFGetSigned(ctx context.Context, req *apiv1.PDFGetSignedRequest) (*apiv1.PDFGetSignedReply, error)
	PDFRevoke(ctx context.Context, req *apiv1.PDFRevokeRequest) (*apiv1.PDFRevokeReply, error)

	Status(ctx context.Context) (*model.Status, error)
}
