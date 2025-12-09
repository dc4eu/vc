package apiv1

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"vc/internal/verifier/db"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// TestGenerateClientID tests client ID generation
func TestGenerateClientID(t *testing.T) {
	// Generate multiple client IDs and verify they're unique and correct format
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := generateClientID()
		require.NoError(t, err)
		assert.Len(t, id, 32, "client ID should be 32 hex characters (16 bytes)")

		// Verify it's valid hex
		_, err = hex.DecodeString(id)
		assert.NoError(t, err, "client ID should be valid hex")

		assert.False(t, ids[id], "client ID should be unique")
		ids[id] = true
	}
}

// TestGenerateClientSecret tests client secret generation
func TestGenerateClientSecret(t *testing.T) {
	// Generate multiple client secrets and verify they're unique
	secrets := make(map[string]bool)
	for i := 0; i < 100; i++ {
		secret, err := generateClientSecret()
		require.NoError(t, err)
		assert.NotEmpty(t, secret)

		// Base64 URL encoded 32 bytes should be 43 characters
		assert.Len(t, secret, 43, "client secret should be 43 base64url characters")

		assert.False(t, secrets[secret], "client secret should be unique")
		secrets[secret] = true
	}
}

// TestHashClientSecret tests client secret hashing with bcrypt
func TestHashClientSecret(t *testing.T) {
	secret := "test-secret-12345"

	hash, err := hashClientSecret(secret)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify the hash is valid bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret))
	assert.NoError(t, err, "hash should verify against original secret")

	// Verify different secrets produce different hashes (or at least don't match)
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong-secret"))
	assert.Error(t, err, "hash should not match different secret")
}

// TestGenerateRegistrationAccessToken tests registration access token generation
func TestGenerateRegistrationAccessToken(t *testing.T) {
	// Generate multiple tokens and verify they're unique
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token, err := generateRegistrationAccessToken()
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Base64 URL encoded 32 bytes should be 43 characters
		assert.Len(t, token, 43, "registration access token should be 43 base64url characters")

		assert.False(t, tokens[token], "registration access token should be unique")
		tokens[token] = true
	}
}

// TestHashRegistrationAccessToken tests registration access token hashing
func TestHashRegistrationAccessToken(t *testing.T) {
	token := "test-token-12345"

	hash, err := hashRegistrationAccessToken(token)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify the hash is correct SHA256
	expectedHash := sha256.Sum256([]byte(token))
	expectedHashHex := hex.EncodeToString(expectedHash[:])
	assert.Equal(t, expectedHashHex, hash)

	// Verify it's 64 hex characters (32 bytes)
	assert.Len(t, hash, 64)
}

// TestVerifyRegistrationAccessToken tests token verification
func TestVerifyRegistrationAccessToken(t *testing.T) {
	token := "test-token-12345"
	hash, err := hashRegistrationAccessToken(token)
	require.NoError(t, err)

	tests := []struct {
		name      string
		token     string
		hash      string
		wantError bool
	}{
		{
			name:      "valid token and hash",
			token:     token,
			hash:      hash,
			wantError: false,
		},
		{
			name:      "wrong token",
			token:     "wrong-token",
			hash:      hash,
			wantError: true,
		},
		{
			name:      "wrong hash",
			token:     token,
			hash:      "0000000000000000000000000000000000000000000000000000000000000000",
			wantError: true,
		},
		{
			name:      "empty token",
			token:     "",
			hash:      hash,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyRegistrationAccessToken(tt.token, tt.hash)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestClientRegistration_validateRegistrationRequest tests registration request validation
func TestClientRegistration_validateRegistrationRequest(t *testing.T) {
	client, _ := CreateTestClientWithMock(nil)

	tests := []struct {
		name    string
		req     *ClientRegistrationRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid minimal request",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			wantErr: false,
		},
		{
			name: "missing redirect_uris",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{},
			},
			wantErr: true,
			errMsg:  "redirect_uris is required",
		},
		{
			name:    "nil request",
			req:     &ClientRegistrationRequest{},
			wantErr: true,
		},
		{
			name: "valid request with multiple redirect URIs",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{
					"https://example.com/callback",
					"https://example.com/callback2",
				},
			},
			wantErr: false,
		},
		{
			name: "valid token endpoint auth method - client_secret_basic",
			req: &ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "client_secret_basic",
			},
			wantErr: false,
		},
		{
			name: "valid token endpoint auth method - client_secret_post",
			req: &ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "client_secret_post",
			},
			wantErr: false,
		},
		{
			name: "valid token endpoint auth method - none",
			req: &ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "none",
			},
			wantErr: false,
		},
		{
			name: "invalid token endpoint auth method",
			req: &ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "invalid_method",
			},
			wantErr: true,
			errMsg:  "unsupported token_endpoint_auth_method",
		},
		{
			name: "valid grant types",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				GrantTypes:   []string{"authorization_code", "refresh_token"},
			},
			wantErr: false,
		},
		{
			name: "invalid grant type",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				GrantTypes:   []string{"implicit"},
			},
			wantErr: true,
			errMsg:  "unsupported grant_type",
		},
		{
			name: "valid response type - code",
			req: &ClientRegistrationRequest{
				RedirectURIs:  []string{"https://example.com/callback"},
				ResponseTypes: []string{"code"},
			},
			wantErr: false,
		},
		{
			name: "invalid response type",
			req: &ClientRegistrationRequest{
				RedirectURIs:  []string{"https://example.com/callback"},
				ResponseTypes: []string{"token"},
			},
			wantErr: true,
			errMsg:  "unsupported response_type",
		},
		{
			name: "valid subject type - public",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				SubjectType:  "public",
			},
			wantErr: false,
		},
		{
			name: "valid subject type - pairwise",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				SubjectType:  "pairwise",
			},
			wantErr: false,
		},
		{
			name: "invalid subject type",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				SubjectType:  "invalid",
			},
			wantErr: true,
			errMsg:  "subject_type must be",
		},
		{
			name: "valid code challenge method - S256",
			req: &ClientRegistrationRequest{
				RedirectURIs:        []string{"https://example.com/callback"},
				CodeChallengeMethod: "S256",
			},
			wantErr: false,
		},
		{
			name: "valid code challenge method - plain",
			req: &ClientRegistrationRequest{
				RedirectURIs:        []string{"https://example.com/callback"},
				CodeChallengeMethod: "plain",
			},
			wantErr: false,
		},
		{
			name: "invalid code challenge method",
			req: &ClientRegistrationRequest{
				RedirectURIs:        []string{"https://example.com/callback"},
				CodeChallengeMethod: "invalid",
			},
			wantErr: true,
			errMsg:  "code_challenge_method must be",
		},
		{
			name: "both jwks_uri and jwks not allowed",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				JWKSUri:      "https://example.com/.well-known/jwks.json",
				JWKS:         map[string]any{"keys": []any{}},
			},
			wantErr: true,
			errMsg:  "cannot specify both jwks_uri and jwks",
		},
		{
			name: "valid logo_uri",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				LogoURI:      "https://example.com/logo.png",
			},
			wantErr: false,
		},
		{
			name: "invalid logo_uri - http not allowed",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				LogoURI:      "http://example.com/logo.png",
			},
			wantErr: true,
			errMsg:  "logo_uri",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.validateRegistrationRequest(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestClientRegistration_applyRegistrationDefaults tests default value application
func TestClientRegistration_applyRegistrationDefaults(t *testing.T) {
	client, _ := CreateTestClientWithMock(nil)

	req := &ClientRegistrationRequest{
		RedirectURIs: []string{"https://example.com/callback"},
	}

	client.applyRegistrationDefaults(req)

	// Check defaults are applied
	assert.Equal(t, "client_secret_basic", req.TokenEndpointAuthMethod)
	assert.Contains(t, req.ResponseTypes, "code")
	assert.Contains(t, req.GrantTypes, "authorization_code")
}

// TestAuthenticateClient tests client authentication
func TestAuthenticateClient(t *testing.T) {
	ctx := context.Background()
	client, mockDB := CreateTestClientWithMock(nil)

	// Create a test client with a known secret hash
	// The authenticateClient compares SHA256 of provided secret with SHA256 of stored hash
	testSecret := "test-client-secret"
	testSecretHash := sha256.Sum256([]byte(testSecret))
	testSecretHashStr := hex.EncodeToString(testSecretHash[:])

	mockDB.Clients.AddClient(&db.Client{
		ClientID:         "test-client",
		ClientSecretHash: testSecretHashStr, // Store the hash
	})

	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		wantErr      error
		wantClient   bool
	}{
		{
			name:         "valid credentials",
			clientID:     "test-client",
			clientSecret: testSecretHashStr, // Provide the hash as secret (it will SHA256 it again)
			wantErr:      nil,
			wantClient:   true,
		},
		{
			name:         "unknown client",
			clientID:     "unknown-client",
			clientSecret: "any-secret",
			wantErr:      ErrInvalidClient,
			wantClient:   false,
		},
		{
			name:         "wrong secret",
			clientID:     "test-client",
			clientSecret: "wrong-secret",
			wantErr:      ErrInvalidClient,
			wantClient:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := client.authenticateClient(ctx, tt.clientID, tt.clientSecret)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				if tt.wantClient {
					assert.NotNil(t, result)
					assert.Equal(t, tt.clientID, result.ClientID)
				}
			}
		})
	}
}
