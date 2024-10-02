package apiv1

import (
	"context"
)

type EventPublisher interface {
	MockNext(mockNextRequest *MockNextRequest) error
	Close(ctx context.Context) error
}
