package httpserver

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/internal/registry/apiv1"
)

// Apiv1 interface
type Apiv1 interface {
	Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)

	// Token Status List endpoints
	StatusLists(ctx context.Context, req *apiv1.StatusListsRequest) (*apiv1.StatusListsResponse, error)
	StatusListAggregation(ctx context.Context) (*apiv1.StatusListAggregationResponse, error)

	// Admin GUI endpoints
	SearchPerson(ctx context.Context, req *apiv1.SearchPersonRequest) (*apiv1.SearchPersonReply, error)
	UpdateStatus(ctx context.Context, req *apiv1.UpdateStatusRequest) error
}
