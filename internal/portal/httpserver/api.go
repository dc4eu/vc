package httpserver

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
	"vc/pkg/vcclient"
)

// Apiv1 interface
type Apiv1 interface {
	Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)

	GetUserCredentialOffers(ctx context.Context, request *vcclient.LoginPIDUserRequest) (*model.SearchDocumentsReply, error)

	// Deprecated: use GetCredentialOffers
	SearchDocuments(ctx context.Context, request *model.SearchDocumentsRequest) (*model.SearchDocumentsReply, error)
}
