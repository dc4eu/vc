//go:build saml

package httpserver

import (
	"context"
	"net/http"
)

// registerSAMLRoutes registers SAML-specific endpoints when SAML is enabled
func (s *Service) registerSAMLRoutes(ctx context.Context, rgRoot interface{}) {
	rgSAML := rgRoot.(interface {
		Group(string) interface{}
	}).Group("/saml")

	s.httpHelpers.Server.RegEndpoint(ctx, rgSAML, http.MethodGet, "/metadata", http.StatusOK, s.endpointSAMLMetadata)
	s.httpHelpers.Server.RegEndpoint(ctx, rgSAML, http.MethodPost, "/initiate", http.StatusOK, s.endpointSAMLInitiate)
	s.httpHelpers.Server.RegEndpoint(ctx, rgSAML, http.MethodPost, "/acs", http.StatusOK, s.endpointSAMLACS)

	s.log.Info("SAML endpoints registered")
}
