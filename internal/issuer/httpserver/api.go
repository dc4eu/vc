package httpserver

import (
	"context"
	"wallet/internal/issuer/apiv1"
	"wallet/pkg/model"
)

// Apiv1 interface
type Apiv1 interface {
	SignPDF(ctx context.Context, req *apiv1.SignPDFRequest) (*apiv1.SignPDFReply, error)
	GetSignedPDF(ctx context.Context, req *apiv1.GetSignedPDFRequest) (*apiv1.GetSignedPDFReply, error)
	Status(ctx context.Context) (*model.Status, error)
}
