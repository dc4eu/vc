package httpserver

import (
	"context"
	"vc/internal/mock_as/apiv1"
)

// Apiv1 interface
type Apiv1 interface {
	MockNext(ctx context.Context, indata *apiv1.MockNextRequest) (*apiv1.MockNextReply, error)
}
