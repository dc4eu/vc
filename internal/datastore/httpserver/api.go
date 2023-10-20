package httpserver

import (
	"context"
	"vc/internal/datastore/apiv1"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/pkg/model"
)

// Apiv1 interface
type Apiv1 interface {
	Upload(ctx context.Context, req *model.Upload) (*apiv1.UploadReply, error)
	IDMapping(ctx context.Context, reg *model.MetaData) (*apiv1.IDMappingReply, error)
	GetDocument(ctx context.Context, req *apiv1.GetDocumentRequest) (*apiv1.GetDocumentReply, error)
	GetDocumentByCollectionCode(ctx context.Context, req *model.MetaData) (*apiv1.GetDocumentReply, error)
	ListMetadata(ctx context.Context, req *apiv1.ListMetadataRequest) (*apiv1.ListMetadataReply, error)
	Portal(ctx context.Context, req *apiv1.PortalRequest) (*apiv1.PortalReply, error)

	Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
