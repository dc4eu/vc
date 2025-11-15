package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestSessionStatus tests the SessionStatus type and constants
func TestSessionStatus(t *testing.T) {
	tests := []struct {
		name   string
		status SessionStatus
		want   string
	}{
		{"Pending", SessionStatusPending, "pending"},
		{"Awaiting Presentation", SessionStatusAwaitingPresentation, "awaiting_presentation"},
		{"Code Issued", SessionStatusCodeIssued, "code_issued"},
		{"Token Issued", SessionStatusTokenIssued, "token_issued"},
		{"Completed", SessionStatusCompleted, "completed"},
		{"Expired", SessionStatusExpired, "expired"},
		{"Error", SessionStatusError, "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.status))
		})
	}
}

// TestSession_Creation tests session structure creation
func TestSession_Creation(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(5 * time.Minute)

	session := &Session{
		ID:        "session-123",
		CreatedAt: now,
		ExpiresAt: expiresAt,
		Status:    SessionStatusPending,
		OIDCRequest: OIDCRequest{
			ClientID:    "client-1",
			RedirectURI: "https://example.com/callback",
			Scope:       "openid profile",
			State:       "state-456",
			Nonce:       "nonce-789",
		},
	}

	assert.NotNil(t, session)
	assert.Equal(t, "session-123", session.ID)
	assert.Equal(t, SessionStatusPending, session.Status)
	assert.Equal(t, "client-1", session.OIDCRequest.ClientID)
	assert.True(t, session.ExpiresAt.After(session.CreatedAt))
}

// TestSession_WithTokens tests session with tokens
func TestSession_WithTokens(t *testing.T) {
	now := time.Now()

	session := &Session{
		ID:        "session-123",
		CreatedAt: now,
		Status:    SessionStatusTokenIssued,
		Tokens: TokenSet{
			AuthorizationCode:     "code-abc",
			AuthorizationCodeUsed: false,
			CodeExpiresAt:         now.Add(5 * time.Minute),
			AccessToken:           "access-xyz",
			AccessTokenExpiresAt:  now.Add(1 * time.Hour),
			IDToken:               "id-token-123",
			RefreshToken:          "refresh-456",
			RefreshTokenExpiresAt: now.Add(24 * time.Hour),
			TokenType:             "Bearer",
		},
	}

	assert.Equal(t, "code-abc", session.Tokens.AuthorizationCode)
	assert.False(t, session.Tokens.AuthorizationCodeUsed)
	assert.Equal(t, "Bearer", session.Tokens.TokenType)
	assert.NotEmpty(t, session.Tokens.AccessToken)
	assert.NotEmpty(t, session.Tokens.RefreshToken)
}

// TestSession_WithVerifiedClaims tests session with verified claims
func TestSession_WithVerifiedClaims(t *testing.T) {
	session := &Session{
		ID:     "session-123",
		Status: SessionStatusCompleted,
		VerifiedClaims: map[string]any{
			"sub":         "user-123",
			"given_name":  "John",
			"family_name": "Doe",
			"birthdate":   "1990-01-01",
		},
	}

	assert.NotNil(t, session.VerifiedClaims)
	assert.Equal(t, "user-123", session.VerifiedClaims["sub"])
	assert.Equal(t, "John", session.VerifiedClaims["given_name"])
	assert.Len(t, session.VerifiedClaims, 4)
}

// TestOIDCRequest_WithPKCE tests OIDC request with PKCE
func TestOIDCRequest_WithPKCE(t *testing.T) {
	request := OIDCRequest{
		ClientID:            "client-1",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid pid",
		State:               "state-123",
		Nonce:               "nonce-456",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		ResponseType:        "code",
		ResponseMode:        "query",
	}

	assert.Equal(t, "client-1", request.ClientID)
	assert.Equal(t, "S256", request.CodeChallengeMethod)
	assert.NotEmpty(t, request.CodeChallenge)
	assert.Equal(t, "code", request.ResponseType)
}

// TestOIDCRequest_WithOptionalParameters tests OIDC request with optional parameters
func TestOIDCRequest_WithOptionalParameters(t *testing.T) {
	request := OIDCRequest{
		ClientID:    "client-1",
		RedirectURI: "https://example.com/callback",
		Scope:       "openid profile email",
		Display:     "page",
		Prompt:      "consent",
		MaxAge:      3600,
		UILocales:   []string{"en", "sv"},
		LoginHint:   "user@example.com",
		ACRValues:   []string{"urn:mace:incommon:iap:silver"},
	}

	assert.Equal(t, "page", request.Display)
	assert.Equal(t, "consent", request.Prompt)
	assert.Equal(t, 3600, request.MaxAge)
	assert.Len(t, request.UILocales, 2)
	assert.Contains(t, request.UILocales, "en")
	assert.Equal(t, "user@example.com", request.LoginHint)
}

// TestOpenID4VPSession tests OpenID4VP session structure
func TestOpenID4VPSession(t *testing.T) {
	presentationDef := map[string]any{
		"id": "pd-123",
		"input_descriptors": []any{
			map[string]any{
				"id":   "pid",
				"name": "PID Credential",
			},
		},
	}

	submission := map[string]any{
		"id":            "sub-123",
		"definition_id": "pd-123",
	}

	vp := OpenID4VPSession{
		PresentationDefinition: presentationDef,
		RequestObjectNonce:     "nonce-123",
		VPToken:                "eyJhbGc...",
		PresentationSubmission: submission,
		WalletID:               "wallet-456",
	}

	assert.NotNil(t, vp.PresentationDefinition)
	assert.Equal(t, "nonce-123", vp.RequestObjectNonce)
	assert.Equal(t, "wallet-456", vp.WalletID)
	assert.NotEmpty(t, vp.VPToken)
}

// TestTokenSet_AuthorizationCodeFlow tests token set for authorization code flow
func TestTokenSet_AuthorizationCodeFlow(t *testing.T) {
	now := time.Now()

	tokens := TokenSet{
		AuthorizationCode:     "auth-code-123",
		AuthorizationCodeUsed: false,
		CodeExpiresAt:         now.Add(5 * time.Minute),
	}

	assert.NotEmpty(t, tokens.AuthorizationCode)
	assert.False(t, tokens.AuthorizationCodeUsed)
	assert.True(t, tokens.CodeExpiresAt.After(now))

	// Simulate code usage
	tokens.AuthorizationCodeUsed = true
	assert.True(t, tokens.AuthorizationCodeUsed)
}

// TestTokenSet_CompleteTokens tests complete token set
func TestTokenSet_CompleteTokens(t *testing.T) {
	now := time.Now()

	tokens := TokenSet{
		AuthorizationCode:     "code-123",
		AuthorizationCodeUsed: true,
		CodeExpiresAt:         now.Add(5 * time.Minute),
		AccessToken:           "access-xyz",
		AccessTokenExpiresAt:  now.Add(1 * time.Hour),
		IDToken:               "eyJhbGc...id-token",
		RefreshToken:          "refresh-abc",
		RefreshTokenExpiresAt: now.Add(30 * 24 * time.Hour),
		TokenType:             "Bearer",
	}

	assert.True(t, tokens.AuthorizationCodeUsed)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.IDToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.Equal(t, "Bearer", tokens.TokenType)

	// Verify expiration times are in correct order
	assert.True(t, tokens.CodeExpiresAt.Before(tokens.AccessTokenExpiresAt))
	assert.True(t, tokens.AccessTokenExpiresAt.Before(tokens.RefreshTokenExpiresAt))
}

// TestClient_Structure tests client structure
func TestClient_Structure(t *testing.T) {
	client := &Client{
		ClientID:         "client-123",
		ClientSecretHash: "$2a$10$...",
		RedirectURIs: []string{
			"https://example.com/callback",
			"https://app.example.com/auth",
		},
		GrantTypes: []string{
			"authorization_code",
			"refresh_token",
		},
		ResponseTypes: []string{
			"code",
		},
		TokenEndpointAuthMethod: "client_secret_post",
		AllowedScopes: []string{
			"openid",
			"profile",
			"email",
			"pid",
		},
		SubjectType: "public",
		RequirePKCE: true,
	}

	assert.Equal(t, "client-123", client.ClientID)
	assert.NotEmpty(t, client.ClientSecretHash)
	assert.Len(t, client.RedirectURIs, 2)
	assert.Contains(t, client.GrantTypes, "authorization_code")
	assert.True(t, client.RequirePKCE)
	assert.Equal(t, "public", client.SubjectType)
}

// TestClient_PairwiseSubject tests client with pairwise subject
func TestClient_PairwiseSubject(t *testing.T) {
	client := &Client{
		ClientID:    "client-pairwise",
		SubjectType: "pairwise",
		AllowedScopes: []string{
			"openid",
			"pid",
		},
	}

	assert.Equal(t, "pairwise", client.SubjectType)
}

// TestClient_WithJWKS tests client with JWKS configuration
func TestClient_WithJWKS(t *testing.T) {
	jwks := map[string]any{
		"keys": []any{
			map[string]any{
				"kty": "RSA",
				"use": "sig",
				"kid": "key-1",
			},
		},
	}

	client := &Client{
		ClientID:                "client-jwks",
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKS:                    jwks,
	}

	assert.NotNil(t, client.JWKS)
	assert.Equal(t, "private_key_jwt", client.TokenEndpointAuthMethod)
}

// TestClient_WithJWKSUri tests client with JWKS URI
func TestClient_WithJWKSUri(t *testing.T) {
	client := &Client{
		ClientID:                "client-jwks-uri",
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKSUri:                 "https://example.com/.well-known/jwks.json",
	}

	assert.Equal(t, "https://example.com/.well-known/jwks.json", client.JWKSUri)
}

// TestClient_PublicClient tests public client (no secret)
func TestClient_PublicClient(t *testing.T) {
	client := &Client{
		ClientID:                "public-client",
		ClientSecretHash:        "", // No secret for public clients
		TokenEndpointAuthMethod: "none",
		RequirePKCE:             true, // Public clients must use PKCE
		GrantTypes: []string{
			"authorization_code",
		},
	}

	assert.Empty(t, client.ClientSecretHash)
	assert.Equal(t, "none", client.TokenEndpointAuthMethod)
	assert.True(t, client.RequirePKCE)
}

// TestClient_ConfidentialClient tests confidential client
func TestClient_ConfidentialClient(t *testing.T) {
	client := &Client{
		ClientID:                "confidential-client",
		ClientSecretHash:        "$2a$10$hashed_secret",
		TokenEndpointAuthMethod: "client_secret_post",
		RequirePKCE:             false, // Optional for confidential clients
		GrantTypes: []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
		},
	}

	assert.NotEmpty(t, client.ClientSecretHash)
	assert.Equal(t, "client_secret_post", client.TokenEndpointAuthMethod)
	assert.Contains(t, client.GrantTypes, "client_credentials")
}

// TestClient_DefaultScopes tests client with default scopes
func TestClient_DefaultScopes(t *testing.T) {
	client := &Client{
		ClientID: "client-defaults",
		AllowedScopes: []string{
			"openid",
			"profile",
			"email",
			"pid",
			"address",
		},
		DefaultScopes: []string{
			"openid",
			"profile",
		},
	}

	assert.Len(t, client.AllowedScopes, 5)
	assert.Len(t, client.DefaultScopes, 2)
	assert.Contains(t, client.DefaultScopes, "openid")
	assert.Contains(t, client.AllowedScopes, "pid")
}

// TestSession_StatusTransitions tests session status transitions
func TestSession_StatusTransitions(t *testing.T) {
	now := time.Now()
	session := &Session{
		ID:        "session-status-test",
		CreatedAt: now,
		ExpiresAt: now.Add(10 * time.Minute),
		Status:    SessionStatusPending,
	}

	// Test status progression
	assert.Equal(t, SessionStatusPending, session.Status)

	session.Status = SessionStatusAwaitingPresentation
	assert.Equal(t, SessionStatusAwaitingPresentation, session.Status)

	session.Status = SessionStatusCodeIssued
	assert.Equal(t, SessionStatusCodeIssued, session.Status)

	session.Status = SessionStatusTokenIssued
	assert.Equal(t, SessionStatusTokenIssued, session.Status)

	session.Status = SessionStatusCompleted
	assert.Equal(t, SessionStatusCompleted, session.Status)
}

// TestSession_Expiration tests session expiration logic
func TestSession_Expiration(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		expiresAt time.Time
		isExpired bool
	}{
		{"Not expired - 5 minutes future", now.Add(5 * time.Minute), false},
		{"Not expired - 1 hour future", now.Add(1 * time.Hour), false},
		{"Expired - 1 minute past", now.Add(-1 * time.Minute), true},
		{"Expired - 1 hour past", now.Add(-1 * time.Hour), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				ID:        "session-exp-test",
				CreatedAt: now.Add(-10 * time.Minute),
				ExpiresAt: tt.expiresAt,
				Status:    SessionStatusPending,
			}

			isExpired := now.After(session.ExpiresAt)
			assert.Equal(t, tt.isExpired, isExpired)
		})
	}
}

// TestTokenSet_Expiration tests token expiration
func TestTokenSet_Expiration(t *testing.T) {
	now := time.Now()

	tokens := TokenSet{
		AuthorizationCode:     "code-123",
		CodeExpiresAt:         now.Add(-1 * time.Minute), // Expired
		AccessToken:           "access-456",
		AccessTokenExpiresAt:  now.Add(30 * time.Minute), // Valid
		RefreshToken:          "refresh-789",
		RefreshTokenExpiresAt: now.Add(7 * 24 * time.Hour), // Valid
	}

	// Check code expiration
	assert.True(t, now.After(tokens.CodeExpiresAt), "Authorization code should be expired")

	// Check access token
	assert.False(t, now.After(tokens.AccessTokenExpiresAt), "Access token should be valid")

	// Check refresh token
	assert.False(t, now.After(tokens.RefreshTokenExpiresAt), "Refresh token should be valid")
}

// TestClient_MultipleRedirectURIs tests client with multiple redirect URIs
func TestClient_MultipleRedirectURIs(t *testing.T) {
	client := &Client{
		ClientID: "multi-redirect-client",
		RedirectURIs: []string{
			"https://example.com/callback",
			"https://example.com/callback2",
			"http://localhost:8080/callback",
			"myapp://callback",
		},
	}

	assert.Len(t, client.RedirectURIs, 4)
	assert.Contains(t, client.RedirectURIs, "https://example.com/callback")
	assert.Contains(t, client.RedirectURIs, "myapp://callback")
}

// Benchmark tests for structure operations

func BenchmarkSession_Creation(b *testing.B) {
	now := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = &Session{
			ID:        "session-bench",
			CreatedAt: now,
			ExpiresAt: now.Add(5 * time.Minute),
			Status:    SessionStatusPending,
			OIDCRequest: OIDCRequest{
				ClientID:    "client-1",
				RedirectURI: "https://example.com/callback",
				Scope:       "openid profile",
			},
		}
	}
}

func BenchmarkTokenSet_Creation(b *testing.B) {
	now := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = &TokenSet{
			AuthorizationCode:     "code-123",
			AuthorizationCodeUsed: false,
			CodeExpiresAt:         now.Add(5 * time.Minute),
			AccessToken:           "access-xyz",
			AccessTokenExpiresAt:  now.Add(1 * time.Hour),
			TokenType:             "Bearer",
		}
	}
}
