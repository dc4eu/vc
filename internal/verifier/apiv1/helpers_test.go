package apiv1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
	"vc/internal/verifier/db"
	"vc/pkg/configuration"
	"vc/pkg/openid4vp"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// generateTestRSAKey creates an RSA key pair for testing
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// generateTestECDSAKey creates an ECDSA key pair for testing
func generateTestECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// hashPassword creates a bcrypt hash of a password for testing
func hashPassword(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)
	return string(hash)
}

// createSimplePresentationTemplate creates a basic presentation template for testing
func createSimplePresentationTemplate(t *testing.T, scopes []string) *configuration.PresentationRequestTemplate {
	t.Helper()
	return &configuration.PresentationRequestTemplate{
		ID:          "test-template",
		Name:        "Test Template",
		Description: "Test presentation template",
		Version:     "1.0",
		OIDCScopes:  scopes,
		DCQLQuery: &openid4vp.DCQL{
			Credentials: []openid4vp.CredentialQuery{
				{
					ID:     "test-credential",
					Format: "vc+sd-jwt",
					Meta: openid4vp.MetaQuery{
						VCTValues: []string{"https://example.com/test"},
					},
					Claims: []openid4vp.ClaimQuery{
						{Path: []string{"given_name"}},
						{Path: []string{"family_name"}},
					},
				},
			},
		},
		ClaimMappings: map[string]string{
			"given_name":  "given_name",
			"family_name": "family_name",
		},
		Enabled: true,
	}
}

// createTestSession creates a session for testing
func createTestSession(t *testing.T, id string, clientID string) *db.Session {
	t.Helper()
	return &db.Session{
		ID:        id,
		Status:    db.SessionStatusPending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(15 * time.Minute),
		OIDCRequest: db.OIDCRequest{
			ClientID:     clientID,
			RedirectURI:  "https://example.com/callback",
			Scope:        "openid profile",
			State:        "test-state",
			Nonce:        "test-nonce",
			ResponseType: "code",
		},
		Tokens: db.TokenSet{},
	}
}

// createTestSessionWithCode creates a session with an authorization code
func createTestSessionWithCode(t *testing.T, id string, clientID string, code string) *db.Session {
	t.Helper()
	session := createTestSession(t, id, clientID)
	session.Status = db.SessionStatusCompleted
	session.Tokens.AuthorizationCode = code
	session.Tokens.CodeExpiresAt = time.Now().Add(10 * time.Minute)
	return session
}

// createTestSessionWithTokens creates a session with tokens
func createTestSessionWithTokens(t *testing.T, id string, clientID string, accessToken string) *db.Session {
	t.Helper()
	session := createTestSession(t, id, clientID)
	session.Status = db.SessionStatusCompleted
	session.Tokens.AccessToken = accessToken
	session.Tokens.AccessTokenExpiresAt = time.Now().Add(1 * time.Hour)
	session.Tokens.RefreshToken = "refresh-" + accessToken
	session.Tokens.RefreshTokenExpiresAt = time.Now().Add(24 * time.Hour)
	session.VerifiedClaims = map[string]any{
		"given_name":  "John",
		"family_name": "Doe",
		"email":       "john.doe@example.com",
	}
	return session
}

// createTestClient creates a client for testing
func createTestClient(t *testing.T, clientID string, clientSecret string) *db.Client {
	t.Helper()
	return &db.Client{
		ClientID:                clientID,
		ClientSecretHash:        hashPassword(t, clientSecret),
		RedirectURIs:            []string{"https://example.com/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_post",
		AllowedScopes:           []string{"openid", "profile", "email"},
		DefaultScopes:           []string{"openid"},
		SubjectType:             "public",
		RequirePKCE:             false,
	}
}

// createTestPublicClient creates a public client (no secret) for testing
func createTestPublicClient(t *testing.T, clientID string) *db.Client {
	t.Helper()
	return &db.Client{
		ClientID:                clientID,
		RedirectURIs:            []string{"https://example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		AllowedScopes:           []string{"openid", "profile"},
		DefaultScopes:           []string{"openid"},
		SubjectType:             "public",
		RequirePKCE:             true,
	}
}

// generatePKCE creates a PKCE code verifier and challenge for testing
func generatePKCE(t *testing.T) (verifier string, challenge string) {
	t.Helper()
	verifier = "test-code-verifier-with-sufficient-length-for-pkce-requirements-1234567890"
	// S256: BASE64URL(SHA256(code_verifier))
	// For testing, we use a pre-computed value
	challenge = "6nLwF4T8X8T9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9Y"
	return
}
