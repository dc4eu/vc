//go:build oidcrp

package httpserver

import (
	"vc/pkg/oidcrp"
)

// OIDCRPService is the actual OIDC RP service when OIDC RP is enabled
type OIDCRPService = *oidcrp.Service
