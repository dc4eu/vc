//go:build !oidcrp

package httpserver

import (
	"context"

	"github.com/gin-gonic/gin"
)

// registerOIDCRPRoutes is a no-op when OIDC RP is not enabled
func (s *Service) registerOIDCRPRoutes(ctx context.Context, rgRoot *gin.RouterGroup) {
	// OIDC RP support disabled at compile time
}
