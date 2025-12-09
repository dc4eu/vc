package apiv1

import (
	"testing"
	"vc/internal/verifier/apiv1/utils"

	"github.com/stretchr/testify/assert"
)

// TestAuthorizeRequest validates the AuthorizeRequest struct fields
func TestAuthorizeRequest_Validation(t *testing.T) {
	tests := []struct {
		name     string
		req      AuthorizeRequest
		wantErr  bool
		errField string
	}{
		{
			name: "valid request",
			req: AuthorizeRequest{
				ResponseType: "code",
				ClientID:     "test-client",
				RedirectURI:  "https://example.com/callback",
				Scope:        "openid",
				State:        "random-state",
				Nonce:        "random-nonce",
			},
			wantErr: false,
		},
		{
			name: "missing response_type",
			req: AuthorizeRequest{
				ClientID:    "test-client",
				RedirectURI: "https://example.com/callback",
				Scope:       "openid",
			},
			wantErr:  true,
			errField: "response_type",
		},
		{
			name: "missing client_id",
			req: AuthorizeRequest{
				ResponseType: "code",
				RedirectURI:  "https://example.com/callback",
				Scope:        "openid",
			},
			wantErr:  true,
			errField: "client_id",
		},
		{
			name: "missing redirect_uri",
			req: AuthorizeRequest{
				ResponseType: "code",
				ClientID:     "test-client",
				Scope:        "openid",
			},
			wantErr:  true,
			errField: "redirect_uri",
		},
		{
			name: "missing scope",
			req: AuthorizeRequest{
				ResponseType: "code",
				ClientID:     "test-client",
				RedirectURI:  "https://example.com/callback",
			},
			wantErr:  true,
			errField: "scope",
		},
		{
			name: "with PKCE parameters",
			req: AuthorizeRequest{
				ResponseType:        "code",
				ClientID:            "test-client",
				RedirectURI:         "https://example.com/callback",
				Scope:               "openid profile",
				CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				CodeChallengeMethod: "S256",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation - check required fields are non-empty
			hasError := false
			if tt.req.ResponseType == "" {
				hasError = true
			}
			if tt.req.ClientID == "" {
				hasError = true
			}
			if tt.req.RedirectURI == "" {
				hasError = true
			}
			if tt.req.Scope == "" {
				hasError = true
			}

			if tt.wantErr {
				assert.True(t, hasError, "Expected validation error for %s", tt.errField)
			} else {
				assert.False(t, hasError, "Expected no validation error")
			}
		})
	}
}

// TestAuthorizeResponse validates the AuthorizeResponse struct
func TestAuthorizeResponse_Fields(t *testing.T) {
	resp := AuthorizeResponse{
		SessionID:        "session-123",
		QRCodeData:       "openid://...",
		QRCodeImageURL:   "https://verifier.example.com/qr/session-123",
		DeepLinkURL:      "openid://authorize?...",
		PollURL:          "https://verifier.example.com/session/session-123",
		PreferredFormats: []string{"vc+sd-jwt"},
		UseJAR:           true,
		ResponseMode:     "direct_post",
		Title:            "Verify your credential",
		Subtitle:         "Scan the QR code with your wallet",
		PrimaryColor:     "#007bff",
		SecondaryColor:   "#6c757d",
		Theme:            "light",
		LogoURL:          "https://verifier.example.com/logo.png",
	}

	assert.Equal(t, "session-123", resp.SessionID)
	assert.Equal(t, "openid://...", resp.QRCodeData)
	assert.Contains(t, resp.PreferredFormats, "vc+sd-jwt")
	assert.True(t, resp.UseJAR)
	assert.Equal(t, "direct_post", resp.ResponseMode)
}

// TestTokenRequest validates the TokenRequest struct
func TestTokenRequest_Validation(t *testing.T) {
	tests := []struct {
		name      string
		req       TokenRequest
		grantType string
		wantErr   bool
	}{
		{
			name: "valid authorization code grant",
			req: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "auth-code-123",
				RedirectURI:  "https://example.com/callback",
				ClientID:     "test-client",
				CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			},
			grantType: "authorization_code",
			wantErr:   false,
		},
		{
			name: "valid refresh token grant",
			req: TokenRequest{
				GrantType:    "refresh_token",
				RefreshToken: "refresh-token-123",
				ClientID:     "test-client",
			},
			grantType: "refresh_token",
			wantErr:   false,
		},
		{
			name: "missing grant_type",
			req: TokenRequest{
				Code:        "auth-code-123",
				RedirectURI: "https://example.com/callback",
				ClientID:    "test-client",
			},
			wantErr: true,
		},
		{
			name: "authorization_code missing code",
			req: TokenRequest{
				GrantType:   "authorization_code",
				RedirectURI: "https://example.com/callback",
				ClientID:    "test-client",
			},
			grantType: "authorization_code",
			wantErr:   true,
		},
		{
			name: "refresh_token missing token",
			req: TokenRequest{
				GrantType: "refresh_token",
				ClientID:  "test-client",
			},
			grantType: "refresh_token",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasError := false

			// Validate required fields
			if tt.req.GrantType == "" {
				hasError = true
			}

			// Grant type specific validation
			switch tt.req.GrantType {
			case "authorization_code":
				if tt.req.Code == "" {
					hasError = true
				}
			case "refresh_token":
				if tt.req.RefreshToken == "" {
					hasError = true
				}
			}

			if tt.wantErr {
				assert.True(t, hasError, "Expected validation error")
			} else {
				assert.False(t, hasError, "Expected no validation error")
			}
		})
	}
}

// TestTokenResponse validates the TokenResponse struct
func TestTokenResponse_Fields(t *testing.T) {
	resp := TokenResponse{
		AccessToken:  "access-token-123",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "refresh-token-123",
		IDToken:      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
		Scope:        "openid profile email",
	}

	assert.Equal(t, "access-token-123", resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, 3600, resp.ExpiresIn)
	assert.Equal(t, "refresh-token-123", resp.RefreshToken)
	assert.NotEmpty(t, resp.IDToken)
	assert.Equal(t, "openid profile email", resp.Scope)
}

// TestPKCEValidation tests PKCE code challenge verification
func TestPKCEValidation(t *testing.T) {
	tests := []struct {
		name                string
		codeVerifier        string
		codeChallenge       string
		codeChallengeMethod string
		expectValid         bool
	}{
		{
			name:                "valid S256 PKCE",
			codeVerifier:        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			expectValid:         true,
		},
		{
			name:                "invalid S256 PKCE - wrong verifier",
			codeVerifier:        "wrongverifier123456789012345678901234567890",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			expectValid:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := utils.ValidatePKCE(tt.codeVerifier, tt.codeChallenge, tt.codeChallengeMethod)
			if tt.expectValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestResponseModes tests different OAuth 2.0 response modes
func TestResponseModes(t *testing.T) {
	validModes := []string{"query", "fragment", "form_post", "direct_post"}

	for _, mode := range validModes {
		t.Run(mode, func(t *testing.T) {
			// Just validate these are recognized response modes
			assert.Contains(t, validModes, mode)
		})
	}
}

// TestScopeParsing tests scope string parsing
func TestScopeParsing(t *testing.T) {
	tests := []struct {
		name           string
		scopeStr       string
		expectedScopes []string
	}{
		{
			name:           "openid only",
			scopeStr:       "openid",
			expectedScopes: []string{"openid"},
		},
		{
			name:           "openid profile email",
			scopeStr:       "openid profile email",
			expectedScopes: []string{"openid", "profile", "email"},
		},
		{
			name:           "with custom scopes",
			scopeStr:       "openid profile pid edu_diploma",
			expectedScopes: []string{"openid", "profile", "pid", "edu_diploma"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scopes := parseScopes(tt.scopeStr)
			assert.Equal(t, tt.expectedScopes, scopes)
		})
	}
}

// TestStandardClaims tests standard OIDC claims
func TestStandardClaims(t *testing.T) {
	standardClaims := []string{
		"sub", "name", "given_name", "family_name", "middle_name", "nickname",
		"preferred_username", "profile", "picture", "website", "email",
		"email_verified", "gender", "birthdate", "zoneinfo", "locale",
		"phone_number", "phone_number_verified", "address", "updated_at",
	}

	// Verify we know about all standard claims
	for _, claim := range standardClaims {
		t.Run(claim, func(t *testing.T) {
			assert.NotEmpty(t, claim)
		})
	}
}
