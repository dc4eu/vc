package httpserver

import (
	"context"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/internal/ui/apiv1"
	"vc/internal/ui/representations"
)

// Apiv1 interface
type Apiv1 interface {
	//Upload(ctx context.Context, req *model.Upload) (*apiv1.UploadReply, error)
	//IDMapping(ctx context.Context, reg *model.MetaData) (*apiv1.IDMappingReply, error)
	//GetDocument(ctx context.Context, req *apiv1.GetDocumentRequest) (*apiv1.GetDocumentReply, error)
	//GetDocumentByCollectCode(ctx context.Context, req *model.MetaData) (*apiv1.GetDocumentReply, error)
	//ListMetadata(ctx context.Context, req *apiv1.ListMetadataRequest) (*apiv1.ListMetadataReply, error)
	//Portal(ctx context.Context, req *apiv1.PortalRequest) (*apiv1.PortalReply, error)

	Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
	Login(ctx context.Context, req *apiv1.LoginRequest) (*apiv1.LoggedinReply, error)
	Logout(ctx context.Context) error
	User(ctx context.Context) (*apiv1.LoggedinReply, error)
	Portal(ctx context.Context, req *representations.PortalRequest) (*any, error)
}