package httpserver

import (
	"context"
	"vc/internal/datastore/apiv1"
	"vc/internal/datastore/db"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/pkg/model"
	"vc/pkg/pda1"
)

// Apiv1 interface
type Apiv1 interface {
	EHICUpload(ctx context.Context, req *apiv1.EHICUploadRequest) (*apiv1.EHICUploadReply, error)
	EHICID(ctx context.Context, req *apiv1.EHICIDRequest) (*db.EHICUpload, error)

	PDA1Upload(ctx context.Context, req *apiv1.PDA1UploadRequest) (*apiv1.PDA1UploadReply, error)
	PDA1ID(ctx context.Context, req *apiv1.PDA1IDRequest) (*db.PDA1Upload, error)
	PDA1Search(ctx context.Context, req *apiv1.PDA1SearchRequest) (*pda1.Document, error)

	GenericUpload(ctx context.Context, req *model.GenericUpload) (*apiv1.GenericUploadReply, error)
	GenericList(ctx context.Context, req *model.GenericAttributes) (*apiv1.GenericListReply, error)
	GenericDocument(ctx context.Context, req *model.GenericAttributes) (*apiv1.GenericDocumentReply, error)
	GenericQR(ctx context.Context, req *model.GenericAttributes) (*apiv1.GenericQRReply, error)

	LadokUpload(ctx context.Context, req *apiv1.LadokUploadRequest) (*apiv1.LadokUploadReply, error)
	LadokID(ctx context.Context, req *apiv1.LadokIDRequest) (*db.LadokUpload, error)

	Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
