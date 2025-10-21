package httpserver

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/internal/verifier/apiv1"
	"vc/pkg/model"
	"vc/pkg/oauth2"
)

type Apiv1 interface {
	// oauth2
	OAuthMetadata(ctx context.Context) (*oauth2.AuthorizationServerMetadata, error)

	// vp-datastore
	PaginatedVerificationRecords(ctx context.Context, request *apiv1.PaginatedVerificationRecordsRequest) (*apiv1.PaginatedVerificationRecordsReply, error)

	// openid4vp-web

	// misc
	CredentialInfo(ctx context.Context) (map[string]*model.CredentialConstructor, error)
	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)

	GetRequestObject(ctx context.Context, req *apiv1.GetRequestObjectRequest) (map[string]any, error)
}
