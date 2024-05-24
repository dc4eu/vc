package httpserver

import (
	"context"
	"vc/internal/apigw/apiv1"
	apiv1_issuer "vc/internal/gen/issuer/apiv1.issuer"
	apiv1_status "vc/internal/gen/status/apiv1.status"
)

// Apiv1 interface
type Apiv1 interface {
	// datastore endpoints
	Upload(ctx context.Context, req *apiv1.UploadRequest) error
	Notification(ctx context.Context, req *apiv1.NotificationRequest) (*apiv1.NotificationReply, error)
	IDMapping(ctx context.Context, reg *apiv1.IDMappingRequest) (*apiv1.IDMappingReply, error)
	GetDocument(ctx context.Context, req *apiv1.GetDocumentRequest) (*apiv1.GetDocumentReply, error)
	DeleteDocument(ctx context.Context, req *apiv1.DeleteDocumentRequest) error
	GetDocumentCollectID(ctx context.Context, req *apiv1.GetDocumentCollectIDRequest) (*apiv1.GetDocumentCollectIDReply, error)
	RevokeDocument(ctx context.Context, req *apiv1.RevokeDocumentRequest) error
	Portal(ctx context.Context, req *apiv1.PortalRequest) (*apiv1.PortalReply, error)

	// credential endpoints
	Revoke(ctx context.Context, req *apiv1.RevokeRequest) (*apiv1.RevokeReply, error)
	Credential(ctx context.Context, req *apiv1.CredentialRequest) (*apiv1_issuer.MakeSDJWTReply, error)

	// misc endpoints
	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
