package httpserver

import (
	"context"
	"vc/internal/apigw/apiv1"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
	"vc/pkg/openid4vci"
)

// Apiv1 interface
type Apiv1 interface {
	// datastore endpoints
	Upload(ctx context.Context, req *apiv1.UploadRequest) error
	Notification(ctx context.Context, req *apiv1.NotificationRequest) (*apiv1.NotificationReply, error)
	AddDocumentIdentity(ctx context.Context, req *apiv1.AddDocumentIdentityRequest) error
	DeleteDocumentIdentity(ctx context.Context, req *apiv1.DeleteDocumentIdentityRequest) error
	IdentityMapping(ctx context.Context, reg *apiv1.IdentityMappingRequest) (*apiv1.IdentityMappingReply, error)
	GetDocument(ctx context.Context, req *apiv1.GetDocumentRequest) (*apiv1.GetDocumentReply, error)
	DocumentList(ctx context.Context, req *apiv1.DocumentListRequest) (*apiv1.DocumentListReply, error)
	DeleteDocument(ctx context.Context, req *apiv1.DeleteDocumentRequest) error
	GetDocumentCollectID(ctx context.Context, req *apiv1.GetDocumentCollectIDRequest) (*apiv1.GetDocumentCollectIDReply, error)
	RevokeDocument(ctx context.Context, req *apiv1.RevokeDocumentRequest) error
	AddConsent(ctx context.Context, req *apiv1.AddConsentRequest) error
	GetConsent(ctx context.Context, req *apiv1.GetConsentRequest) (*model.Consent, error)

	// datastore endpoints - disabled in production
	SearchDocuments(ctx context.Context, req *model.SearchDocumentsRequest) (*model.SearchDocumentsReply, error)

	// OpenID4VCI endpoints
	OIDCAuth(ctx context.Context, req *openid4vci.AuthorizationRequest) (string, error)
	OIDCToken(ctx context.Context, req *openid4vci.TokenRequest) (*openid4vci.TokenResponse, error)
	OIDCNonce(ctx context.Context) (*openid4vci.NonceResponse, error)
	OIDCCredential(ctx context.Context, req *openid4vci.CredentialRequest) (*openid4vci.CredentialResponse, error)
	OIDCDeferredCredential(ctx context.Context, req *openid4vci.DeferredCredentialRequest) (*openid4vci.DeferredCredentialResponse, error)
	OIDCNotification(ctx context.Context, req *openid4vci.NotificationRequest) error
	OIDCMetadata(ctx context.Context) (*openid4vci.CredentialIssuerMetadataParameters, error)
	OIDCBatchCredential(ctx context.Context, req *openid4vci.BatchCredentialRequest) (*openid4vci.BatchCredentialResponse, error)

	//JWKS(ctx context.Context) (*apiv1_issuer.JwksReply, error)
	//Revoke(ctx context.Context, req *apiv1.RevokeRequest) (*apiv1.RevokeReply, error)

	// misc endpoints
	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
