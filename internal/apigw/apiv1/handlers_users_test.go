package apiv1

import (
	"context"
	"testing"
	"time"
	"vc/internal/apigw/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/sdjwtvc"
	"vc/pkg/trace"
	"vc/pkg/vcclient"

	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
)

// setupTestMongoDB creates a MongoDB testcontainer and returns the database service
func setupTestMongoDB(ctx context.Context, t *testing.T) (*db.Service, func()) {
	mongoContainer, err := mongodb.Run(ctx, "mongo:6")
	require.NoError(t, err)

	connStr, err := mongoContainer.ConnectionString(ctx)
	require.NoError(t, err)

	// Create configuration
	cfg := &model.Cfg{
		Common: model.Common{
			Mongo: model.Mongo{
				URI: connStr,
			},
		},
	}

	// Create tracer
	log, _ := logger.New("test", "", false)
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	// Create database service
	dbService, err := db.New(ctx, cfg, tracer, log)
	require.NoError(t, err)

	cleanup := func() {
		dbService.Close(ctx)
		tracer.Shutdown(ctx)
		if err := mongoContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	}

	return dbService, cleanup
}

// TestUserLookup_BasicAuth tests the UserLookup function with basic username/password authentication.
// This simulates the traditional authentication flow (not PID auth).
func TestUserLookup_BasicAuth(t *testing.T) {
	ctx := context.Background()
	log, _ := logger.New("test", "", false)

	// Setup MongoDB testcontainer
	dbService, cleanup := setupTestMongoDB(ctx, t)
	defer cleanup()

	// Insert test user
	testUser := &model.OAuthUsers{
		Username: "testuser",
		Password: "$2a$10$abcdefghijklmnopqrstuv", // bcrypt hash placeholder
		Identity: &model.Identity{
			GivenName:               "John",
			FamilyName:              "Doe",
			BirthDate:               "1990-01-01",
			ExpiryDate:              "2030-01-01",
			Schema:                  &model.IdentitySchema{Name: "SE", Version: "1.0.0"},
			AuthenticSourcePersonID: "test-person-123",
		},
	}
	err := dbService.VCUsersColl.Save(ctx, testUser)
	require.NoError(t, err)

	// Insert authorization context
	testAuthContext := &model.AuthorizationContext{
		SessionID:           "session-123",
		RequestURI:          "https://issuer.example.com/request/123",
		Code:                "auth-code-123",
		State:               "state-456",
		WalletURI:           "https://wallet.example.com/callback",
		ClientID:            "test-client",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(1 * time.Hour).Unix(),
		VCT:                 "urn:eudi:pid:1",
	}
	err = dbService.VCAuthorizationContextColl.Save(ctx, testAuthContext)
	require.NoError(t, err)

	client := &Client{
		log: log,
		db:  dbService,
	}

	req := &vcclient.UserLookupRequest{
		RequestURI: "https://issuer.example.com/request/123",
		Username:   "testuser",
		AuthMethod: model.AuthMethodBasic,
	}

	result, err := client.UserLookup(ctx, req)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.RedirectURL, "https://wallet.example.com/callback")
	assert.Contains(t, result.RedirectURL, "code=auth-code-123")
	assert.Contains(t, result.RedirectURL, "state=state-456")

	assert.Equal(t, "John", result.SVGTemplateClaims["given_name"].Value)
	assert.Equal(t, "Given name", result.SVGTemplateClaims["given_name"].Label)
	assert.Equal(t, "Doe", result.SVGTemplateClaims["family_name"].Value)
	assert.Equal(t, "Family name", result.SVGTemplateClaims["family_name"].Label)
	assert.Equal(t, "1990-01-01", result.SVGTemplateClaims["birth_date"].Value)
	assert.Equal(t, "2030-01-01", result.SVGTemplateClaims["expiry_date"].Value)
}

// TestUserLookup_PIDAuth tests the UserLookup function with PID authentication (OpenID4VP).
// This simulates authentication using verifiable credentials presented by the wallet.
func TestUserLookup_PIDAuth(t *testing.T) {
	ctx := context.Background()
	log, _ := logger.New("test", "", false)

	// Setup MongoDB testcontainer
	dbService, cleanup := setupTestMongoDB(ctx, t)
	defer cleanup()

	// Insert authorization context for PID auth
	testAuthContext := &model.AuthorizationContext{
		SessionID:            "session-456",
		VerifierResponseCode: "response-code-xyz",
		Code:                 "auth-code-789",
		State:                "state-abc",
		WalletURI:            "https://wallet.example.com/callback",
		ClientID:             "test-client",
		CodeChallenge:        "challenge",
		CodeChallengeMethod:  "S256",
		ExpiresAt:            time.Now().Add(1 * time.Hour).Unix(),
		RequestURI:           "https://issuer.example.com/request/456",
		VCT:                  "urn:eudi:pid:1",
		AuthenticSource:      "test-source",
	}
	err := dbService.VCAuthorizationContextColl.Save(ctx, testAuthContext)
	require.NoError(t, err)

	// Create document cache with test data
	cache := ttlcache.New[string, map[string]*model.CompleteDocument]()
	doc := model.CompleteDocument{
		Meta: &model.MetaData{
			AuthenticSource: "test-source",
			VCT:             "urn:eudi:pid:1",
			DocumentVersion: "1.0.0",
			DocumentID:      "doc-123",
		},
		DocumentData: map[string]any{
			"given_name":  "Jane",
			"family_name": "Smith",
			"birth_date":  "1985-05-15",
		},
		Identities: []model.Identity{
			{
				GivenName:               "Jane",
				FamilyName:              "Smith",
				BirthDate:               "1985-05-15",
				Schema:                  &model.IdentitySchema{Name: "SE", Version: "1.0.0"},
				AuthenticSourcePersonID: "test-person-456",
			},
		},
		DocumentDisplay: &model.DocumentDisplay{
			Version: "1.0.0",
			Type:    "secure",
			DescriptionStructured: map[string]any{
				"en": "Personal ID",
			},
		},
		DocumentDataVersion: "1.0.0",
	}
	docs := map[string]*model.CompleteDocument{
		"test-source": &doc,
	}
	cache.Set("session-456", docs, ttlcache.DefaultTTL)

	client := &Client{
		log:           log,
		documentCache: cache,
		db:            dbService,
	}

	// Create VCTM with claims
	givenNamePath := "given_name"
	familyNamePath := "family_name"
	birthDatePath := "birth_date"

	req := &vcclient.UserLookupRequest{
		RequestURI:   "https://issuer.example.com/request/456",
		ResponseCode: "response-code-xyz",
		AuthMethod:   model.AuthMethodPID,
		VCTM: &sdjwtvc.VCTM{
			Claims: []sdjwtvc.Claim{
				{
					Path:  []*string{&givenNamePath},
					SVGID: "given_name",
					Display: []sdjwtvc.ClaimDisplay{
						{Label: "Given Name"},
					},
				},
				{
					Path:  []*string{&familyNamePath},
					SVGID: "family_name",
					Display: []sdjwtvc.ClaimDisplay{
						{Label: "Family Name"},
					},
				},
				{
					Path:  []*string{&birthDatePath},
					SVGID: "birth_date",
					Display: []sdjwtvc.ClaimDisplay{
						{Label: "Birth Date"},
					},
				},
			},
		},
	}

	result, err := client.UserLookup(ctx, req)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.RedirectURL, "https://wallet.example.com/callback")
	assert.Contains(t, result.RedirectURL, "code=auth-code-789")
	assert.Contains(t, result.RedirectURL, "state=state-abc")

	assert.Equal(t, "Jane", result.SVGTemplateClaims["given_name"].Value)
	assert.Equal(t, "Given Name", result.SVGTemplateClaims["given_name"].Label)
	assert.Equal(t, "Smith", result.SVGTemplateClaims["family_name"].Value)
	assert.Equal(t, "Family Name", result.SVGTemplateClaims["family_name"].Label)
	assert.Equal(t, "1985-05-15", result.SVGTemplateClaims["birth_date"].Value)
	assert.Equal(t, "Birth Date", result.SVGTemplateClaims["birth_date"].Label)
}

// TestUserLookup_PIDAuth_NoDocuments tests error handling when no documents are found in cache for PID auth.
func TestUserLookup_PIDAuth_NoDocuments(t *testing.T) {
	ctx := context.Background()
	log, _ := logger.New("test", "", false)

	// Setup MongoDB testcontainer
	dbService, cleanup := setupTestMongoDB(ctx, t)
	defer cleanup()

	// Insert authorization context
	testAuthContext := &model.AuthorizationContext{
		SessionID:            "session-no-docs",
		VerifierResponseCode: "response-code-123",
		Code:                 "auth-code",
		State:                "state",
		WalletURI:            "https://wallet.example.com/callback",
		ClientID:             "test-client",
		CodeChallenge:        "challenge",
		CodeChallengeMethod:  "S256",
		ExpiresAt:            time.Now().Add(1 * time.Hour).Unix(),
		RequestURI:           "https://issuer.example.com/request/789",
		VCT:                  "urn:eudi:pid:1",
	}
	err := dbService.VCAuthorizationContextColl.Save(ctx, testAuthContext)
	require.NoError(t, err)

	// Create empty document cache
	cache := ttlcache.New[string, map[string]*model.CompleteDocument]()

	client := &Client{
		log:           log,
		documentCache: cache,
		db:            dbService,
	}

	req := &vcclient.UserLookupRequest{
		RequestURI:   "https://issuer.example.com/request/789",
		ResponseCode: "response-code-123",
		AuthMethod:   model.AuthMethodPID,
		VCTM:         &sdjwtvc.VCTM{Claims: []sdjwtvc.Claim{}},
	}

	result, err := client.UserLookup(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no documents found for session")
}

func TestUserLookup_UnsupportedAuthMethod(t *testing.T) {
	ctx := context.Background()
	log, _ := logger.New("test", "", false)

	// Setup MongoDB testcontainer
	dbService, cleanup := setupTestMongoDB(ctx, t)
	defer cleanup()

	// Insert authorization context
	testAuthContext := &model.AuthorizationContext{
		SessionID:           "session-999",
		RequestURI:          "https://issuer.example.com/request/999",
		Code:                "auth-code",
		State:               "state",
		WalletURI:           "https://wallet.example.com/callback",
		ClientID:            "test-client",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(1 * time.Hour).Unix(),
		VCT:                 "urn:eudi:pid:1",
	}
	err := dbService.VCAuthorizationContextColl.Save(ctx, testAuthContext)
	require.NoError(t, err)

	client := &Client{
		log: log,
		db:  dbService,
	}

	req := &vcclient.UserLookupRequest{
		RequestURI: "https://issuer.example.com/request/999",
		AuthMethod: "unsupported_method",
	}

	result, err := client.UserLookup(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "unsupported auth method")
}

func TestUserLookup_ClaimExtraction(t *testing.T) {
	// Test the claim extraction logic in isolation
	documentData := map[string]any{
		"given_name":  "John",
		"family_name": "Doe",
		"birth_date":  "1990-01-01",
	}

	givenNamePath := "given_name"
	familyNamePath := "family_name"
	birthDatePath := "birth_date"

	vctm := &sdjwtvc.VCTM{
		Claims: []sdjwtvc.Claim{
			{
				Path:  []*string{&givenNamePath},
				SVGID: "given_name",
				Display: []sdjwtvc.ClaimDisplay{
					{Label: "Given Name"},
				},
			},
			{
				Path:  []*string{&familyNamePath},
				SVGID: "family_name",
				Display: []sdjwtvc.ClaimDisplay{
					{Label: "Family Name"},
				},
			},
			{
				Path:  []*string{&birthDatePath},
				SVGID: "birth_date",
				Display: []sdjwtvc.ClaimDisplay{
					{Label: "Birth Date"},
				},
			},
		},
	}

	jsonPaths, err := vctm.ClaimJSONPath()
	require.NoError(t, err)

	claimValues, err := sdjwtvc.ExtractClaimsByJSONPath(documentData, jsonPaths.Displayable)
	require.NoError(t, err)

	assert.Equal(t, "John", claimValues["given_name"])
	assert.Equal(t, "Doe", claimValues["family_name"])
	assert.Equal(t, "1990-01-01", claimValues["birth_date"])

	// Build SVG template claims as done in UserLookup
	svgTemplateClaims := map[string]vcclient.SVGClaim{}
	for _, claim := range vctm.Claims {
		value, ok := claimValues[claim.SVGID].(string)
		if !ok {
			continue
		}

		if claim.SVGID != "" {
			svgTemplateClaims[claim.SVGID] = vcclient.SVGClaim{
				Label: claim.Display[0].Label,
				Value: value,
			}
		}
	}

	assert.Equal(t, "John", svgTemplateClaims["given_name"].Value)
	assert.Equal(t, "Given Name", svgTemplateClaims["given_name"].Label)
	assert.Equal(t, "Doe", svgTemplateClaims["family_name"].Value)
	assert.Equal(t, "Family Name", svgTemplateClaims["family_name"].Label)
	assert.Equal(t, "1990-01-01", svgTemplateClaims["birth_date"].Value)
	assert.Equal(t, "Birth Date", svgTemplateClaims["birth_date"].Label)
}
