package apiv1

import (
	"context"
	"vc/pkg/vcclient"
)

type EventPublisher interface {
	Upload(uploadRequest *vcclient.UploadRequest) error
	Close(ctx context.Context) error
}
