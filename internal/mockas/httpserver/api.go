package httpserver

import (
	"context"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/internal/mockas/apiv1"
)

// Apiv1 interface
type Apiv1 interface {
	MockNext(ctx context.Context, indata *apiv1.MockNextRequest) (*apiv1.MockNextReply, error)
	MockBulk(ctx context.Context, inData *apiv1.MockBulkRequest) (*apiv1.MockBulkReply, error)

	Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
