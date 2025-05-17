package httpserver

import (
	"context"
	"vc/internal/apigw/apiv1"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"
	"vc/pkg/vcclient"
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

	// SatosaCredential endpoints, remove after transition from Satosa to OIDC4VCI
	SatosaCredential(ctx context.Context, req *apiv1.CredentialRequest) (*apiv1_issuer.MakeSDJWTReply, error)
	JWKS(ctx context.Context) (*apiv1_issuer.JwksReply, error)

	// datastore endpoints - disabled in production
	SearchDocuments(ctx context.Context, req *model.SearchDocumentsRequest) (*model.SearchDocumentsReply, error)
	AddPIDUser(ctx context.Context, req *vcclient.AddPIDRequest) error
	LoginPIDUser(ctx context.Context, req *vcclient.LoginPIDUserRequest) (*vcclient.LoginPIDUserReply, error)

	// OpenID4VCI endpoints
	OIDCNonce(ctx context.Context) (*openid4vci.NonceResponse, error)
	OIDCCredential(ctx context.Context, req *openid4vci.CredentialRequest) (*openid4vci.CredentialResponse, error)
	OIDCredentialOfferURI(ctx context.Context, req *openid4vci.CredentialOfferURIRequest) (*openid4vci.CredentialOfferParameters, error)
	OIDCDeferredCredential(ctx context.Context, req *openid4vci.DeferredCredentialRequest) (*openid4vci.CredentialResponse, error)
	OIDCNotification(ctx context.Context, req *openid4vci.NotificationRequest) error
	OIDCMetadata(ctx context.Context) (*openid4vci.CredentialIssuerMetadataParameters, error)

	OAuthPar(ctx context.Context, req *openid4vci.PARRequest) (*openid4vci.ParResponse, error)
	OAuthAuthorize(ctx context.Context, req *openid4vci.AuthorizeRequest) (*openid4vci.AuthorizationResponse, error)
	OAuthToken(ctx context.Context, req *openid4vci.TokenRequest) (*openid4vci.TokenResponse, error)
	OAuthMetadata(ctx context.Context) (*oauth2.AuthorizationServerMetadata, error)

	//Revoke(ctx context.Context, req *apiv1.RevokeRequest) (*apiv1.RevokeReply, error)

	// misc endpoints
	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
