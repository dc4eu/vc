package apiv1

import (
	"context"
)

type EventPublisher interface {
	Upload(uploadRequest *UploadRequest) error
	Close(ctx context.Context) error
}
