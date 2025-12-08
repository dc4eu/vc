package apiv1

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
	"vc/pkg/openid4vp"

	"github.com/golang-jwt/jwt/v5"
)

// CreateRequestObject creates and signs an OpenID4VP request object
func (c *Client) CreateRequestObject(ctx context.Context, sessionID string, dcqlQuery *openid4vp.DCQL, nonce string) (string, error) {
	// Determine response mode based on Digital Credentials API configuration
	responseMode := "direct_post"
	if c.cfg.VerifierProxy.DigitalCredentials.Enabled {
		if c.cfg.VerifierProxy.DigitalCredentials.ResponseMode != "" {
			responseMode = c.cfg.VerifierProxy.DigitalCredentials.ResponseMode
		} else {
			responseMode = "dc_api.jwt" // Default for DC API
		}
	}

	// Create request object
	requestObject := &openid4vp.RequestObject{
		ISS:          c.cfg.VerifierProxy.OIDC.Issuer,
		AUD:          "https://self-issued.me/v2",
		IAT:          time.Now().Unix(),
		ResponseType: "vp_token",
		ClientID:     c.cfg.VerifierProxy.OIDC.Issuer,
		Nonce:        nonce,
		ResponseMode: responseMode,
		ResponseURI:  c.cfg.VerifierProxy.ExternalURL + "/verification/direct_post",
		State:        sessionID,
		DCQLQuery:    dcqlQuery,
	}

	// Add vp_formats to client_metadata if Digital Credentials API is enabled
	if c.cfg.VerifierProxy.DigitalCredentials.Enabled {
		vpFormats := c.buildVPFormats()
		if len(vpFormats) > 0 {
			requestObject.ClientMetadata = &openid4vp.ClientMetadata{
				VPFormats: vpFormats,
			}
		}
	}

	// Sign the request object
	signedJWT, err := requestObject.Sign(jwt.SigningMethodRS256, c.oidcSigningKey, nil)
	if err != nil {
		c.log.Error(err, "Failed to sign request object")
		return "", err
	}

	// Cache the request object
	c.requestObjectCache.Set(sessionID, requestObject, 5*time.Minute)

	return signedJWT, nil
}

// buildVPFormats constructs the vp_formats object based on configured preferred formats
func (c *Client) buildVPFormats() map[string]map[string][]string {
	vpFormats := make(map[string]map[string][]string)

	preferredFormats := c.cfg.VerifierProxy.DigitalCredentials.PreferredFormats
	if len(preferredFormats) == 0 {
		// Default to SD-JWT if no preferences specified
		preferredFormats = []string{"vc+sd-jwt"}
	}

	for _, format := range preferredFormats {
		switch format {
		case "vc+sd-jwt", "dc+sd-jwt":
			// SD-JWT format with supported algorithms
			vpFormats[format] = map[string][]string{
				"alg": {"ES256", "ES384", "ES512", "RS256"},
			}
		case "mso_mdoc":
			// mdoc format with supported algorithms
			vpFormats["mso_mdoc"] = map[string][]string{
				"alg": {"ES256", "ES384", "ES512"},
			}
		}
	}

	return vpFormats
}

// createDCQLQuery maps OIDC scopes to OpenID4VP DCQL query
func (c *Client) createDCQLQuery(scopes []string) (*openid4vp.DCQL, error) {
	// If presentation builder is configured, use template-based approach
	if c.presentationBuilder != nil {
		dcql, _, err := c.presentationBuilder.BuildFromScopes(context.Background(), scopes)
		if err != nil {
			c.log.Info("Failed to build DCQL query from templates, falling back to legacy mapping", "error", err)
			// Fall through to legacy behavior
		} else {
			return dcql, nil
		}
	}

	// Legacy behavior: use hard-coded scope mapping from config
	credentialQueries := []openid4vp.CredentialQuery{}

	for _, scope := range scopes {
		// Skip standard OIDC scopes
		if scope == "openid" || scope == "profile" || scope == "email" {
			continue
		}

		// Check if this scope maps to a configured credential
		for _, credConfig := range c.cfg.VerifierProxy.OpenID4VP.SupportedCredentials {
			for _, credScope := range credConfig.Scopes {
				if credScope == scope {
					// Create credential query for this credential
					credentialQuery := openid4vp.CredentialQuery{
						ID:     fmt.Sprintf("credential_%s", credConfig.VCT),
						Format: "vc+sd-jwt",
						Meta: openid4vp.MetaQuery{
							VCTValues: []string{credConfig.VCT},
						},
					}
					credentialQueries = append(credentialQueries, credentialQuery)
				}
			}
		}
	}

	// If no specific credentials found, create a generic one
	if len(credentialQueries) == 0 {
		credentialQueries = append(credentialQueries, openid4vp.CredentialQuery{
			ID:     "credential_generic",
			Format: "vc+sd-jwt",
			Meta:   openid4vp.MetaQuery{},
		})
	}

	dcql := &openid4vp.DCQL{
		Credentials: credentialQueries,
	}

	return dcql, nil
}

// generateRandomID generates a random ID for presentation definitions
func generateRandomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateNonce creates a cryptographically random nonce
func (c *Client) generateNonce() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
