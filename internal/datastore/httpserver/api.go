package httpserver

import (
	"context"
	"vc/internal/datastore/apiv1"
	"vc/internal/datastore/db"
	"vc/pkg/model"
)

// Apiv1 interface
type Apiv1 interface {
	EHICUpload(ctx context.Context, req *apiv1.EHICUploadRequest) (*apiv1.EHICUploadReply, error)
	EHICID(ctx context.Context, req *apiv1.EHICIDRequest) (*db.EHICUpload, error)

	PDA1Upload(ctx context.Context, req *apiv1.PDA1UploadRequest) (*apiv1.PDA1UploadReply, error)
	PDA1ID(ctx context.Context, req *apiv1.PDA1IDRequest) (*db.PDA1Upload, error)
	PDA1Search(ctx context.Context, req *apiv1.PDA1SearchRequest) (*model.PDA1, error)

	LadokUpload(ctx context.Context, req *apiv1.LadokUploadRequest) (*apiv1.LadokUploadReply, error)
	LadokID(ctx context.Context, req *apiv1.LadokIDRequest) (*db.LadokUpload, error)

	Status(ctx context.Context) (*model.Health, error)
}
