package apiv1

import (
	"context"
	"testing"
	"time"
	"vc/internal/verifier/db"

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
