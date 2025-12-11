package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
	"vc/internal/verifier/db"
	"vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetQRCode tests QR code generation
func TestGetQRCode(t *testing.T) {
	ctx := context.Background()
	client, mockDB := CreateTestClientWithMock(nil)

	// Create a test session
	session := &db.Session{
		ID:        "test-session-123",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Status:    db.SessionStatusPending,
	}
	err := mockDB.Sessions.Create(ctx, session)
	require.NoError(t, err)

	tests := []struct {
		name      string
		req       *GetQRCodeRequest
		wantErr   error
		checkResp func(t *testing.T, resp *GetQRCodeResponse)
	}{
		{
			name: "valid session",
			req: &GetQRCodeRequest{
				SessionID: "test-session-123",
			},
			wantErr: nil,
			checkResp: func(t *testing.T, resp *GetQRCodeResponse) {
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.ImageData)
				// QR code image should be PNG format
				assert.True(t, len(resp.ImageData) > 0)
			},
		},
		{
			name: "session not found",
			req: &GetQRCodeRequest{
				SessionID: "nonexistent-session",
			},
			wantErr: ErrSessionNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.GetQRCode(ctx, tt.req)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				if tt.checkResp != nil {
					tt.checkResp(t, resp)
				}
			}
		})
	}
}

// TestPollSession tests session polling
func TestPollSession(t *testing.T) {
	ctx := context.Background()
	client, mockDB := CreateTestClientWithMock(nil)

	// Create test sessions with different statuses
	pendingSession := &db.Session{
		ID:        "pending-session",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Status:    db.SessionStatusPending,
	}
	err := mockDB.Sessions.Create(ctx, pendingSession)
	require.NoError(t, err)

	codeIssuedSession := &db.Session{
		ID:        "code-issued-session",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Status:    db.SessionStatusCodeIssued,
		OIDCRequest: db.OIDCRequest{
			RedirectURI: "https://example.com/callback",
			State:       "test-state-123",
		},
		Tokens: db.TokenSet{
			AuthorizationCode: "auth-code-xyz",
		},
	}
	err = mockDB.Sessions.Create(ctx, codeIssuedSession)
	require.NoError(t, err)

	tests := []struct {
		name      string
		req       *PollSessionRequest
		wantErr   error
		checkResp func(t *testing.T, resp *PollSessionResponse)
	}{
		{
			name: "pending session",
			req: &PollSessionRequest{
				SessionID: "pending-session",
			},
			wantErr: nil,
			checkResp: func(t *testing.T, resp *PollSessionResponse) {
				assert.Equal(t, string(db.SessionStatusPending), resp.Status)
				assert.Empty(t, resp.RedirectURI)
			},
		},
		{
			name: "code issued session",
			req: &PollSessionRequest{
				SessionID: "code-issued-session",
			},
			wantErr: nil,
			checkResp: func(t *testing.T, resp *PollSessionResponse) {
				assert.Equal(t, string(db.SessionStatusCodeIssued), resp.Status)
				assert.NotEmpty(t, resp.RedirectURI)
				assert.Contains(t, resp.RedirectURI, "code=auth-code-xyz")
				assert.Contains(t, resp.RedirectURI, "state=test-state-123")
			},
		},
		{
			name: "session not found",
			req: &PollSessionRequest{
				SessionID: "nonexistent-session",
			},
			wantErr: ErrSessionNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.PollSession(ctx, tt.req)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				if tt.checkResp != nil {
					tt.checkResp(t, resp)
				}
			}
		})
	}
}

// TestGetUserInfo tests the UserInfo endpoint
func TestGetUserInfo(t *testing.T) {
	ctx := context.Background()
	client, mockDB := CreateTestClientWithMock(nil)

	// Create a session with verified claims
	session := &db.Session{
		ID:        "userinfo-session",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Status:    db.SessionStatusTokenIssued,
		OIDCRequest: db.OIDCRequest{
			ClientID: "test-client",
			Scope:    "openid profile email",
		},
		Tokens: db.TokenSet{
			AccessToken:          "test-access-token-123",
			AccessTokenExpiresAt: time.Now().Add(1 * time.Hour),
		},
		VerifiedClaims: map[string]any{
			"sub":   "user-123",
			"name":  "John Doe",
			"email": "john@example.com",
		},
	}
	err := mockDB.Sessions.Create(ctx, session)
	require.NoError(t, err)

	tests := []struct {
		name      string
		req       *UserInfoRequest
		wantErr   error
		checkResp func(t *testing.T, resp UserInfoResponse)
	}{
		{
			name: "valid access token",
			req: &UserInfoRequest{
				AccessToken: "test-access-token-123",
			},
			wantErr: nil,
			checkResp: func(t *testing.T, resp UserInfoResponse) {
				assert.Equal(t, "user-123", resp["sub"])
				assert.Equal(t, "John Doe", resp["name"])
				assert.Equal(t, "john@example.com", resp["email"])
			},
		},
		{
			name: "invalid access token",
			req: &UserInfoRequest{
				AccessToken: "invalid-token",
			},
			wantErr: ErrInvalidGrant,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.GetUserInfo(ctx, tt.req)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				if tt.checkResp != nil {
					tt.checkResp(t, resp)
				}
			}
		})
	}
}

// TestGenerateNonce tests nonce generation
func TestGenerateNonce(t *testing.T) {
	client, _ := CreateTestClientWithMock(nil)

	// Generate multiple nonces and verify they're unique
	nonces := make(map[string]bool)
	for i := 0; i < 100; i++ {
		nonce := client.generateNonce()
		assert.NotEmpty(t, nonce)
		assert.False(t, nonces[nonce], "nonce should be unique")
		nonces[nonce] = true

		// Base64 URL encoded 32 bytes should be 43 characters
		assert.Len(t, nonce, 43, "nonce should be 43 base64url characters")
	}
}

// TestGetOIDCRequestObject tests the GetOIDCRequestObject handler
func TestGetOIDCRequestObject(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		sessionID    string
		sessionSetup func(*db.Session)
		expectError  bool
	}{
		{
			name:      "successful request object generation",
			sessionID: "session-ro-1",
			sessionSetup: func(s *db.Session) {
				s.Status = db.SessionStatusPending
				s.ExpiresAt = time.Now().Add(10 * time.Minute)
				s.OpenID4VP.DCQL = &openid4vp.DCQL{
					Credentials: []openid4vp.CredentialQuery{
						{
							ID:     "test_credential",
							Format: "vc+sd-jwt",
							Meta: openid4vp.MetaQuery{
								VCTValues: []string{"https://example.com/credential/test"},
							},
						},
					},
				}
			},
			expectError: false,
		},
		{
			name:      "expired session",
			sessionID: "session-expired",
			sessionSetup: func(s *db.Session) {
				s.Status = db.SessionStatusPending
				s.ExpiresAt = time.Now().Add(-10 * time.Minute) // Already expired
			},
			expectError: true,
		},
		{
			name:         "session not found",
			sessionID:    "non-existent-session",
			sessionSetup: nil,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, mockDB := CreateTestClientWithMock(nil)

			// Generate RSA key for signing
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			client.SetSigningKeyForTesting(key, "RS256")

			// Setup session if needed
			if tt.sessionSetup != nil {
				session := &db.Session{
					ID:        tt.sessionID,
					Status:    db.SessionStatusPending,
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(10 * time.Minute),
					OIDCRequest: db.OIDCRequest{
						ClientID:    "test-client",
						RedirectURI: "https://client.example.com/callback",
						Scope:       "openid",
					},
					OpenID4VP: db.OpenID4VPSession{},
					Tokens:    db.TokenSet{},
				}
				tt.sessionSetup(session)
				err := mockDB.Sessions.Create(ctx, session)
				require.NoError(t, err)
			}

			req := &GetRequestObjectRequest{
				SessionID: tt.sessionID,
			}

			resp, err := client.GetOIDCRequestObject(ctx, req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, resp)
				assert.NotEmpty(t, resp.RequestObject)

				// Verify nonce was stored in session
				session, _ := mockDB.Sessions.GetByID(ctx, tt.sessionID)
				assert.NotEmpty(t, session.OpenID4VP.RequestObjectNonce)
			}
		})
	}
}

// TestProcessCallback tests the ProcessCallback handler
func TestProcessCallback(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name             string
		sessionID        string
		code             string
		errorParam       string
		sessionSetup     func(*db.Session)
		expectError      bool
		expectErrorInURI bool
	}{
		{
			name:      "successful callback with code",
			sessionID: "session-callback-1",
			code:      "auth-code-123",
			sessionSetup: func(s *db.Session) {
				s.Status = db.SessionStatusCodeIssued
				s.OIDCRequest.RedirectURI = "https://client.example.com/callback"
				s.OIDCRequest.State = "client-state"
			},
			expectError: false,
		},
		{
			name:       "callback with error",
			sessionID:  "session-callback-error",
			errorParam: "access_denied",
			sessionSetup: func(s *db.Session) {
				s.Status = db.SessionStatusPending
				s.OIDCRequest.RedirectURI = "https://client.example.com/callback"
				s.OIDCRequest.State = "client-state"
			},
			expectError:      false,
			expectErrorInURI: true,
		},
		{
			name:         "session not found",
			sessionID:    "non-existent-session",
			code:         "some-code",
			sessionSetup: nil,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, mockDB := CreateTestClientWithMock(nil)

			// Setup session if needed
			if tt.sessionSetup != nil {
				session := &db.Session{
					ID:        tt.sessionID,
					Status:    db.SessionStatusPending,
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(10 * time.Minute),
					OIDCRequest: db.OIDCRequest{
						ClientID:    "test-client",
						RedirectURI: "https://client.example.com/callback",
						Scope:       "openid",
						State:       "client-state",
					},
					Tokens: db.TokenSet{},
				}
				tt.sessionSetup(session)
				err := mockDB.Sessions.Create(ctx, session)
				require.NoError(t, err)
			}

			req := &CallbackRequest{
				State: tt.sessionID,
				Code:  tt.code,
				Error: tt.errorParam,
			}

			resp, err := client.ProcessCallback(ctx, req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, resp)
				assert.NotEmpty(t, resp.RedirectURI)

				if tt.expectErrorInURI {
					assert.Contains(t, resp.RedirectURI, "error=")
				} else {
					assert.Contains(t, resp.RedirectURI, "code=")
				}
				assert.Contains(t, resp.RedirectURI, "state=")
			}
		})
	}
}

// TestGetJWKS_KeyTypes tests the GetJWKS handler with different key types
func TestGetJWKS_KeyTypes(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		setupKey    func() (any, string)
		expectError bool
		expectKty   string
		expectAlg   string
	}{
		{
			name: "RSA key",
			setupKey: func() (any, string) {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return key, "RS256"
			},
			expectError: false,
			expectKty:   "RSA",
			expectAlg:   "RS256",
		},
		{
			name: "EC P-256 key",
			setupKey: func() (any, string) {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return key, "ES256"
			},
			expectError: false,
			expectKty:   "EC",
			expectAlg:   "ES256",
		},
		{
			name: "EC P-384 key",
			setupKey: func() (any, string) {
				key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				return key, "ES384"
			},
			expectError: false,
			expectKty:   "EC",
			expectAlg:   "ES384",
		},
		{
			name: "EC P-521 key",
			setupKey: func() (any, string) {
				key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				return key, "ES512"
			},
			expectError: false,
			expectKty:   "EC",
			expectAlg:   "ES512",
		},
		{
			name: "no key configured",
			setupKey: func() (any, string) {
				return nil, ""
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := CreateTestClientWithMock(nil)

			// Setup key
			key, alg := tt.setupKey()
			if key != nil {
				client.SetSigningKeyForTesting(key, alg)
			}

			jwks, err := client.GetJWKS(ctx)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, jwks)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, jwks)
				require.Len(t, jwks.Keys, 1)
				assert.Equal(t, tt.expectKty, jwks.Keys[0].Kty)
				assert.Equal(t, tt.expectAlg, jwks.Keys[0].Alg)
			}
		})
	}
}
