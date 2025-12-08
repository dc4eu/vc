package apiv1

import (
	"context"
	"testing"
	"vc/pkg/configuration"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
)

// TestCreatePresentationDefinition_PID tests presentation definition for PID scope
func TestCreatePresentationDefinition_PID(t *testing.T) {
	cfg := createTestConfig()
	client := createTestClientWithConfig(t, cfg)

	scopes := []string{"openid", "pid"}

	dcql, err := client.createDCQLQuery(scopes)
	assert.NoError(t, err)
	assert.NotNil(t, dcql)

	// Should return a DCQL struct with credentials
	assert.NotEmpty(t, dcql.Credentials, "Should have at least one credential for PID")
}

// TestCreatePresentationDefinition_MultipleScopes tests presentation definition for multiple scopes
func TestCreatePresentationDefinition_MultipleScopes(t *testing.T) {
	cfg := createTestConfig()
	client := createTestClientWithConfig(t, cfg)

	scopes := []string{"openid", "pid", "email"}

	dcql, err := client.createDCQLQuery(scopes)
	assert.NoError(t, err)
	assert.NotNil(t, dcql)

	// Should have multiple credentials (one for PID, one for email)
	assert.GreaterOrEqual(t, len(dcql.Credentials), 1)
}

// TestCreatePresentationDefinition_OnlyOpenID tests with only openid scope
func TestCreatePresentationDefinition_OnlyOpenID(t *testing.T) {
	cfg := createTestConfig()
	client := createTestClientWithConfig(t, cfg)

	scopes := []string{"openid"}

	dcql, err := client.createDCQLQuery(scopes)
	assert.NoError(t, err)
	assert.NotNil(t, dcql)

	// Should have a generic credential when no specific credentials
	assert.NotEmpty(t, dcql.Credentials)
}

// TestCreatePresentationDefinition_EmptyScopes tests with empty scopes
func TestCreatePresentationDefinition_EmptyScopes(t *testing.T) {
	cfg := createTestConfig()
	client := createTestClientWithConfig(t, cfg)

	scopes := []string{}

	dcql, err := client.createDCQLQuery(scopes)
	assert.NoError(t, err)
	assert.NotNil(t, dcql)

	// Should create a generic DCQL query
	assert.NotEmpty(t, dcql.Credentials)
}

// TestCreatePresentationDefinition_UnsupportedScope tests with unsupported scope
func TestCreatePresentationDefinition_UnsupportedScope(t *testing.T) {
	cfg := createTestConfig()
	client := createTestClientWithConfig(t, cfg)

	scopes := []string{"openid", "unsupported_scope"}

	dcql, err := client.createDCQLQuery(scopes)
	assert.NoError(t, err)
	assert.NotNil(t, dcql)

	// Should still create a DCQL query with generic credentials
	assert.NotEmpty(t, dcql.Credentials)
}

// TestCreateRequestObject tests request object creation
func TestCreateRequestObject(t *testing.T) {
	cfg := createTestConfig()
	client := createTestClientWithConfig(t, cfg)

	sessionID := "test-session-123"
	nonce := "test-nonce-456"
	dcqlQuery := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{
			{
				ID:     "test-credential",
				Format: "vc+sd-jwt",
			},
		},
	}

	// This will fail without proper signing key, but we can test the structure
	requestObject, err := client.CreateRequestObject(context.Background(), sessionID, dcqlQuery, nonce)

	// Expect error because no signing key is configured
	assert.Error(t, err)
	assert.Empty(t, requestObject)
}

// TestGenerateNonce tests nonce generation (already in client_test.go but good to have here too)
func TestGenerateNonce_Uniqueness(t *testing.T) {
	cfg := createTestConfig()
	client := createTestClientWithConfig(t, cfg)

	nonces := make(map[string]bool)
	iterations := 1000

	// Generate many nonces and ensure they're all unique
	for i := 0; i < iterations; i++ {
		nonce := client.generateNonce()
		assert.NotEmpty(t, nonce)
		assert.False(t, nonces[nonce], "Nonce should be unique")
		nonces[nonce] = true
	}

	assert.Len(t, nonces, iterations, "All nonces should be unique")
}

// Helper function to create test configuration with supported credentials
func createTestConfig() *model.Cfg {
	return &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			ExternalURL: "https://verifier.example.com",
			OIDC: model.OIDCConfig{
				Issuer:      "https://verifier.example.com",
				SubjectType: "public",
				SubjectSalt: "test-salt",
			},
			OpenID4VP: model.OpenID4VPConfig{
				PresentationTimeout: 300,
				SupportedCredentials: []model.SupportedCredentialConfig{
					{
						VCT:    "urn:eu:pid:1",
						Scopes: []string{"pid"},
					},
					{
						VCT:    "urn:eu:ehic:1",
						Scopes: []string{"ehic"},
					},
					{
						VCT:    "urn:eu:email:1",
						Scopes: []string{"email"},
					},
				},
			},
		},
	}
}

// Benchmark presentation definition creation
func BenchmarkCreatePresentationDefinition(b *testing.B) {
	cfg := createTestConfig()
	log := logger.NewSimple("bench")
	client := &Client{
		cfg: cfg,
		log: log.New("apiv1"),
	}

	scopes := []string{"openid", "pid", "email"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.createDCQLQuery(scopes)
	}
}

// Benchmark nonce generation
func BenchmarkGenerateNonce(b *testing.B) {
	log := logger.NewSimple("bench")
	client := &Client{log: log.New("apiv1")}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.generateNonce()
	}
}

// TestCreatePresentationDefinition_WithTemplates tests template-based presentation definition
func TestCreatePresentationDefinition_WithTemplates(t *testing.T) {
	ctx := context.Background()

	// Load test templates
	templatesDir := "testdata/presentation_requests"
	config, err := configuration.LoadPresentationRequests(ctx, templatesDir)
	assert.NoError(t, err, "Should load test templates")

	// Create test client with templates
	cfg := createTestConfig()
	log := logger.NewSimple("test")
	client := &Client{
		cfg:                 cfg,
		log:                 log.New("apiv1"),
		presentationBuilder: openid4vp.NewPresentationBuilder(config.GetEnabledTemplates()),
	}

	// Test with PID scope
	scopes := []string{"openid", "pid"}
	dcql, err := client.createDCQLQuery(scopes)
	assert.NoError(t, err)
	assert.NotNil(t, dcql)

	// Verify DCQL structure
	assert.NotEmpty(t, dcql.Credentials, "Should have credentials")

	// Verify the credential query was created from template
	if len(dcql.Credentials) > 0 {
		credential := dcql.Credentials[0]
		assert.NotEmpty(t, credential.ID)
		assert.NotEmpty(t, credential.Format)

		// Check for VCT values in Meta
		assert.NotNil(t, credential.Meta, "Should have Meta with VCT values")
		assert.NotEmpty(t, credential.Meta.VCTValues, "Should have VCT values")
	}
}

// TestCreatePresentationDefinition_TemplatesFallback tests fallback to legacy when template fails
func TestCreatePresentationDefinition_TemplatesFallback(t *testing.T) {
	ctx := context.Background()

	// Load test templates
	templatesDir := "testdata/presentation_requests"
	config, err := configuration.LoadPresentationRequests(ctx, templatesDir)
	assert.NoError(t, err)

	// Create client with templates
	cfg := createTestConfig()
	log := logger.NewSimple("test")
	client := &Client{
		cfg:                 cfg,
		log:                 log.New("apiv1"),
		presentationBuilder: openid4vp.NewPresentationBuilder(config.GetEnabledTemplates()),
	}

	// Test with scope not in templates (should fall back to legacy config)
	scopes := []string{"openid", "ehic"}
	dcql, err := client.createDCQLQuery(scopes)
	assert.NoError(t, err)
	assert.NotNil(t, dcql)

	// Verify DCQL structure from legacy config
	assert.NotEmpty(t, dcql.Credentials, "Should have credentials from legacy config")
}
