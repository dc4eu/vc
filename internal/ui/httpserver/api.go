package httpserver

import (
	"context"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/internal/ui/apiv1"
)

type Apiv1 interface {
	Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
	Login(ctx context.Context, req *apiv1.LoginRequest) (*apiv1.LoggedinReply, error)
	Logout(ctx context.Context) error
	User(ctx context.Context) (*apiv1.LoggedinReply, error)

	StatusAPIGW(ctx context.Context, request *apiv1_status.StatusRequest) (*any, error)
	Portal(ctx context.Context, req *apiv1.PortalRequest) (*any, error)

	MockNext(ctx context.Context, req *apiv1.MockNextRequest) (*any, error)
}
