package httpserver

import (
	"context"
	"wallet/pkg/model"
)

// Apiv1 interface
type Apiv1 interface {
	Status(ctx context.Context) (*model.Status, error)
	MonitoringCertClient(ctx context.Context) (*model.MonitoringCertClients, error)
}
