package httpserver

import (
	"context"
	"vc/internal/apigw/apiv1"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/pkg/model"
)

// Apiv1 interface
type Apiv1 interface {
	Upload(ctx context.Context, req *model.Upload) (*apiv1.UploadReply, error)
	Notification(ctx context.Context, req *apiv1.NotificationRequest) (*apiv1.NotificationReply, error)
	IDMapping(ctx context.Context, reg *model.MetaData) (*apiv1.IDMappingReply, error)
	GetDocument(ctx context.Context, req *apiv1.GetDocumentRequest) (*apiv1.GetDocumentReply, error)
	DeleteDocument(ctx context.Context, req *apiv1.DeleteDocumentRequest) error
	GetDocumentByCollectCode(ctx context.Context, req *model.MetaData) (*apiv1.GetDocumentReply, error)
	ListMetadata(ctx context.Context, req *apiv1.ListMetadataRequest) (*apiv1.ListMetadataReply, error)
	Portal(ctx context.Context, req *apiv1.PortalRequest) (*apiv1.PortalReply, error)

	PDFSign(ctx context.Context, req *apiv1.PDFSignRequest) (*apiv1.PDFSignReply, error)
	PDFValidate(ctx context.Context, req *apiv1.PDFValidateRequest) (*apiv1.PDFValidateReply, error)
	PDFGetSigned(ctx context.Context, req *apiv1.PDFGetSignedRequest) (*apiv1.PDFGetSignedReply, error)
	PDFRevoke(ctx context.Context, req *apiv1.PDFRevokeRequest) (*apiv1.PDFRevokeReply, error)

	Get(ctx context.Context, indata *apiv1.GetRequest) (*apiv1.GetReply, error)
	Revoke(ctx context.Context, req *apiv1.RevokeRequest) (*apiv1.RevokeReply, error)
	Credential(ctx context.Context, req *apiv1.CredentialRequest) (*apiv1.CredentialReply, error)

	SatosaCredential(ctx context.Context, reg *apiv1.SatosaCredentialRequest) (*apiv1.SatosaCredentialReply, error)

	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
