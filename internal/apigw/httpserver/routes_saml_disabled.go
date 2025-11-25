//go:build !saml

package httpserver

import (
	"context"
)

// registerSAMLRoutes is a no-op when SAML is disabled
func (s *Service) registerSAMLRoutes(ctx context.Context, rgRoot interface{}) {
	// SAML not compiled in, no routes to register
	if s.cfg.APIGW.SAML.Enabled {
		s.log.Info("SAML enabled in config but not compiled in. Rebuild with -tags saml")
	}
}
