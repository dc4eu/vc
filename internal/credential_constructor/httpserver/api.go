package httpserver

import (
	"context"
	"vc/internal/credential_constructor/apiv1"
)

// Apiv1 interface
type Apiv1 interface {
	SDJWT(ctx context.Context, indata *apiv1.SDJWTRequest) (*apiv1.SDJWTReply, error)
}
