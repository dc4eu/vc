package httpserver

import (
	"context"
	"vc/internal/issuer/apiv1"
	"vc/pkg/model"

	"github.com/masv3971/gosunetca/types"
)

// Apiv1 interface
type Apiv1 interface {
	PDFSign(ctx context.Context, req *apiv1.PDFSignRequest) (*apiv1.PDFSignReply, error)
	PDFValidate(ctx context.Context, req *apiv1.PDFValidateRequest) (*types.Validation, error)
	PDFGetSigned(ctx context.Context, req *apiv1.PDFGetSignedRequest) (*apiv1.PDFGetSignedReply, error)
	PDFRevoke(ctx context.Context, req *apiv1.PDFRevokeRequest) (*apiv1.PDFRevokeReply, error)

	Status(ctx context.Context) (*model.Health, error)
}
