package integration

import (
	"testing"

	"vc/internal/verifier_proxy/apiv1"

	"github.com/stretchr/testify/assert"
)

// TestDynamicClientRegistration tests the complete client registration flow
func (s *IntegrationSuite) TestDynamicClientRegistration() {
	// Test 1: Register a new client
	registerReq := &apiv1.ClientRegistrationRequest{
		RedirectURIs:            []string{"https://client.example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Test Client",
		ClientURI:               "https://client.example.com",
		Scope:                   "openid profile",
	}

	registerResp, err := s.apiv1.RegisterClient(s.ctx, registerReq)
	assert.NoError(s.t, err)
	assert.NotNil(s.t, registerResp)

	// Verify response
	assert.NotEmpty(s.t, registerResp.ClientID)
	assert.NotEmpty(s.t, registerResp.ClientSecret)
	assert.NotEmpty(s.t, registerResp.RegistrationAccessToken)
	assert.Equal(s.t, []string{"https://client.example.com/callback"}, registerResp.RedirectURIs)
	assert.Equal(s.t, "Test Client", registerResp.ClientName)

	// Test 2: Get client information
	getClientResp, err := s.apiv1.GetClientInformation(s.ctx, registerResp.ClientID, registerResp.RegistrationAccessToken)
	assert.NoError(s.t, err)
	assert.NotNil(s.t, getClientResp)

	assert.Equal(s.t, registerResp.ClientID, getClientResp.ClientID)
	assert.Equal(s.t, "Test Client", getClientResp.ClientName)

	// Test 3: Update client
	updateReq := &apiv1.ClientRegistrationRequest{
		RedirectURIs: []string{"https://client.example.com/callback", "https://client.example.com/callback2"},
		ClientName:   "Updated Test Client",
		ClientURI:    "https://updated.example.com",
	}

	updatedClientResp, err := s.apiv1.UpdateClient(s.ctx, registerResp.ClientID, registerResp.RegistrationAccessToken, updateReq)
	assert.NoError(s.t, err)
	assert.NotNil(s.t, updatedClientResp)

	assert.Equal(s.t, "Updated Test Client", updatedClientResp.ClientName)
	assert.Equal(s.t, "https://updated.example.com", updatedClientResp.ClientURI)
	assert.Len(s.t, updatedClientResp.RedirectURIs, 2)

	// Test 4: Delete client
	err = s.apiv1.DeleteClient(s.ctx, registerResp.ClientID, registerResp.RegistrationAccessToken)
	assert.NoError(s.t, err)

	// Verify client is deleted
	_, err = s.apiv1.GetClientInformation(s.ctx, registerResp.ClientID, registerResp.RegistrationAccessToken)
	assert.Error(s.t, err) // Should fail because client is deleted
}

// TestDynamicClientRegistration_InvalidToken tests authentication with invalid token
func (s *IntegrationSuite) TestDynamicClientRegistration_InvalidToken() {
	// Register a client first
	registerReq := &apiv1.ClientRegistrationRequest{
		RedirectURIs: []string{"https://client.example.com/callback"},
	}

	registerResp, err := s.apiv1.RegisterClient(s.ctx, registerReq)
	assert.NoError(s.t, err)
	assert.NotNil(s.t, registerResp)

	// Try to access with invalid token
	_, err = s.apiv1.GetClientInformation(s.ctx, registerResp.ClientID, "invalid-token-12345")
	assert.Error(s.t, err)
	assert.Equal(s.t, apiv1.ErrInvalidToken, err)
}

// TestDynamicClientRegistration_InvalidRequest tests validation
func (s *IntegrationSuite) TestDynamicClientRegistration_InvalidRequest() {
	testCases := []struct {
		name      string
		request   *apiv1.ClientRegistrationRequest
		wantError bool
	}{
		{
			name: "Missing redirect URIs",
			request: &apiv1.ClientRegistrationRequest{
				ClientName: "Test Client",
			},
			wantError: true,
		},
		{
			name: "Invalid redirect URI with fragment",
			request: &apiv1.ClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/callback#fragment"},
			},
			wantError: true,
		},
		{
			name: "Invalid grant type",
			request: &apiv1.ClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/callback"},
				GrantTypes:   []string{"implicit"},
			},
			wantError: true,
		},
		{
			name: "Valid request",
			request: &apiv1.ClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/callback"},
			},
			wantError: false,
		},
	}

	for _, tc := range testCases {
		s.t.Run(tc.name, func(t *testing.T) {
			resp, err := s.apiv1.RegisterClient(s.ctx, tc.request)

			if tc.wantError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
			}
		})
	}
}

// TestDynamicClientRegistration_DiscoveryMetadata tests that registration endpoint is advertised
func (s *IntegrationSuite) TestDynamicClientRegistration_DiscoveryMetadata() {
	metadata, err := s.apiv1.GetDiscoveryMetadata(s.ctx)
	assert.NoError(s.t, err)
	assert.NotNil(s.t, metadata)

	// Verify registration endpoint is advertised
	assert.NotEmpty(s.t, metadata.RegistrationEndpoint)
	assert.Contains(s.t, metadata.RegistrationEndpoint, "/register")
}

// TestDynamicClientRegistration_WithPKCE tests client registration with PKCE
func (s *IntegrationSuite) TestDynamicClientRegistration_WithPKCE() {
	registerReq := &apiv1.ClientRegistrationRequest{
		RedirectURIs:        []string{"https://client.example.com/callback"},
		CodeChallengeMethod: "S256",
	}

	registerResp, err := s.apiv1.RegisterClient(s.ctx, registerReq)
	assert.NoError(s.t, err)
	assert.NotNil(s.t, registerResp)

	assert.Equal(s.t, "S256", registerResp.CodeChallengeMethod)

	// Verify in database
	client, err := s.db.Clients.GetByClientID(s.ctx, registerResp.ClientID)
	assert.NoError(s.t, err)
	assert.NotNil(s.t, client)
	assert.True(s.t, client.RequirePKCE)
	assert.True(s.t, client.RequireCodeChallenge)
}

// TestDynamicClientRegistration_FullMetadata tests registration with all metadata fields
func (s *IntegrationSuite) TestDynamicClientRegistration_FullMetadata() {
	registerReq := &apiv1.ClientRegistrationRequest{
		RedirectURIs:            []string{"https://client.example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_post",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Full Metadata Client",
		ClientURI:               "https://client.example.com",
		LogoURI:                 "https://client.example.com/logo.png",
		Scope:                   "openid profile email",
		Contacts:                []string{"admin@client.example.com"},
		TosURI:                  "https://client.example.com/tos",
		PolicyURI:               "https://client.example.com/policy",
		SoftwareID:              "software-123",
		SoftwareVersion:         "1.0.0",
		ApplicationType:         "web",
		SubjectType:             "pairwise",
		IDTokenSignedRespAlg:    "ES256",
		DefaultMaxAge:           3600,
		RequireAuthTime:         true,
		DefaultACRValues:        []string{"urn:mace:incommon:iap:silver"},
		CodeChallengeMethod:     "S256",
	}

	registerResp, err := s.apiv1.RegisterClient(s.ctx, registerReq)
	assert.NoError(s.t, err)
	assert.NotNil(s.t, registerResp)

	// Verify all metadata in response
	assert.Equal(s.t, "client_secret_post", registerResp.TokenEndpointAuthMethod)
	assert.Equal(s.t, []string{"authorization_code", "refresh_token"}, registerResp.GrantTypes)
	assert.Equal(s.t, "Full Metadata Client", registerResp.ClientName)
	assert.Equal(s.t, "https://client.example.com", registerResp.ClientURI)
	assert.Equal(s.t, "https://client.example.com/logo.png", registerResp.LogoURI)
	assert.Equal(s.t, "openid profile email", registerResp.Scope)
	assert.Equal(s.t, []string{"admin@client.example.com"}, registerResp.Contacts)
	assert.Equal(s.t, "https://client.example.com/tos", registerResp.TosURI)
	assert.Equal(s.t, "https://client.example.com/policy", registerResp.PolicyURI)
	assert.Equal(s.t, "software-123", registerResp.SoftwareID)
	assert.Equal(s.t, "1.0.0", registerResp.SoftwareVersion)
	assert.Equal(s.t, "web", registerResp.ApplicationType)
	assert.Equal(s.t, "pairwise", registerResp.SubjectType)
	assert.Equal(s.t, "ES256", registerResp.IDTokenSignedRespAlg)
	assert.Equal(s.t, 3600, registerResp.DefaultMaxAge)
	assert.True(s.t, registerResp.RequireAuthTime)
	assert.Equal(s.t, []string{"urn:mace:incommon:iap:silver"}, registerResp.DefaultACRValues)
	assert.Equal(s.t, "S256", registerResp.CodeChallengeMethod)
}

// TestDynamicClientRegistration_InvalidLogoURI tests logo_uri validation
func (s *IntegrationSuite) TestDynamicClientRegistration_InvalidLogoURI() {
	tests := []struct {
		name    string
		logoURI string
		errMsg  string
	}{
		{
			name:    "http scheme not allowed",
			logoURI: "http://client.example.com/logo.png",
			errMsg:  "invalid logo_uri",
		},
		{
			name:    "fragment not allowed",
			logoURI: "https://client.example.com/logo.png#main",
			errMsg:  "must not contain a fragment",
		},
		{
			name:    "invalid url",
			logoURI: "not-a-url",
			errMsg:  "invalid logo_uri",
		},
	}

	for _, tt := range tests {
		s.t.Run(tt.name, func(t *testing.T) {
			registerReq := &apiv1.ClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/callback"},
				ClientName:   "Test Client",
				LogoURI:      tt.logoURI,
			}

			_, err := s.apiv1.RegisterClient(s.ctx, registerReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// TestDynamicClientRegistration_InvalidClientMetadataURIs tests client_uri, policy_uri, tos_uri validation
func (s *IntegrationSuite) TestDynamicClientRegistration_InvalidClientMetadataURIs() {
	tests := []struct {
		name      string
		clientURI string
		policyURI string
		tosURI    string
		errMsg    string
	}{
		{
			name:      "http client_uri not allowed",
			clientURI: "http://client.example.com",
			errMsg:    "invalid client_uri",
		},
		{
			name:      "fragment in policy_uri not allowed",
			policyURI: "https://client.example.com/policy#section",
			errMsg:    "must not contain a fragment",
		},
		{
			name:   "http tos_uri not allowed",
			tosURI: "http://client.example.com/terms",
			errMsg: "invalid tos_uri",
		},
	}

	for _, tt := range tests {
		s.t.Run(tt.name, func(t *testing.T) {
			registerReq := &apiv1.ClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/callback"},
				ClientName:   "Test Client",
				ClientURI:    tt.clientURI,
				PolicyURI:    tt.policyURI,
				TosURI:       tt.tosURI,
			}

			_, err := s.apiv1.RegisterClient(s.ctx, registerReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}
