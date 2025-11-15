package apiv1

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
	"vc/internal/verifier_proxy/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// generateTestRSAKey generates an RSA key pair for testing
func generateTestRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// TestGenerateIDToken tests ID token generation with various claims
func TestGenerateIDToken(t *testing.T) {
	ctx := context.Background()

	// Generate test RSA key
	privateKey, err := generateTestRSAKey()
	if err != nil {
		t.Fatalf("Failed to generate test RSA key: %v", err)
	}

	// Create test client with signing key
	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			ExternalURL: "https://verifier.example.com",
			OIDC: model.OIDCConfig{
				Issuer:      "https://verifier.example.com",
				SubjectType: "public",
				SubjectSalt: "test-salt-12345",
			},
		},
	}

	log := logger.NewSimple("test-idtoken")
	tracer, _ := trace.NewForTesting(ctx, "test", log)

	client, err := New(ctx, nil, cfg, tracer, log)
	assert.NoError(t, err)

	// Set the signing key
	client.oidcSigningKey = privateKey
	client.oidcSigningAlg = "RS256"

	// Create test session with minimal claims
	session := &db.Session{
		OIDCRequest: db.OIDCRequest{
			Nonce: "test-nonce-123",
		},
		OpenID4VP: db.OpenID4VPSession{
			WalletID: "test-wallet-id",
		},
		VerifiedClaims: map[string]any{
			"given_name":  "John",
			"family_name": "Doe",
			"email":       "john.doe@example.com",
		},
	}

	testClient := &db.Client{
		ClientID: "test-client-123",
	}

	// Test ID token generation
	tokenString, err := client.generateIDToken(session, testClient)
	assert.NoError(t, err, "generateIDToken should not error")
	assert.NotEmpty(t, tokenString, "Token string should not be empty")

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			t.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return &privateKey.PublicKey, nil
	})

	assert.NoError(t, err, "Token should parse successfully")
	assert.True(t, token.Valid, "Token should be valid")

	// Verify claims
	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok, "Claims should be MapClaims")

	// Verify standard claims
	assert.Equal(t, "https://verifier.example.com", claims["iss"], "Issuer should match")
	assert.Equal(t, "test-client-123", claims["aud"], "Audience should match client ID")
	assert.Equal(t, "test-nonce-123", claims["nonce"], "Nonce should match")
	assert.NotEmpty(t, claims["sub"], "Subject should be present")
	assert.NotEmpty(t, claims["iat"], "Issued at should be present")
	assert.NotEmpty(t, claims["exp"], "Expiration should be present")

	// Verify custom claims from verified data
	assert.Equal(t, "John", claims["given_name"], "Given name should be in claims")
	assert.Equal(t, "Doe", claims["family_name"], "Family name should be in claims")
	assert.Equal(t, "john.doe@example.com", claims["email"], "Email should be in claims")

	// Verify expiration is in the future
	exp, ok := claims["exp"].(float64)
	assert.True(t, ok, "Expiration should be a number")
	assert.Greater(t, exp, float64(time.Now().Unix()), "Expiration should be in the future")
}

// TestGenerateIDToken_PairwiseSubject tests pairwise subject identifier
func TestGenerateIDToken_PairwiseSubject(t *testing.T) {
	ctx := context.Background()

	privateKey, err := generateTestRSAKey()
	assert.NoError(t, err)

	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			ExternalURL: "https://verifier.example.com",
			OIDC: model.OIDCConfig{
				Issuer:      "https://verifier.example.com",
				SubjectType: "pairwise",
				SubjectSalt: "test-salt-pairwise",
			},
		},
	}

	log := logger.NewSimple("test-idtoken")
	tracer, _ := trace.NewForTesting(ctx, "test", log)

	client, err := New(ctx, nil, cfg, tracer, log)
	assert.NoError(t, err)

	client.oidcSigningKey = privateKey

	session := &db.Session{
		OIDCRequest: db.OIDCRequest{
			Nonce: "nonce-1",
		},
		OpenID4VP: db.OpenID4VPSession{
			WalletID: "wallet-123",
		},
		VerifiedClaims: map[string]any{},
	}

	client1 := &db.Client{ClientID: "client-1"}
	client2 := &db.Client{ClientID: "client-2"}

	// Generate tokens for same wallet, different clients
	token1, err := client.generateIDToken(session, client1)
	assert.NoError(t, err)

	token2, err := client.generateIDToken(session, client2)
	assert.NoError(t, err)

	// Parse both tokens
	parsedToken1, _ := jwt.Parse(token1, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	parsedToken2, _ := jwt.Parse(token2, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})

	claims1 := parsedToken1.Claims.(jwt.MapClaims)
	claims2 := parsedToken2.Claims.(jwt.MapClaims)

	// For pairwise, subjects should be different for different clients
	sub1 := claims1["sub"].(string)
	sub2 := claims2["sub"].(string)
	assert.NotEqual(t, sub1, sub2, "Pairwise subjects should differ for different clients")
}

// TestGenerateIDToken_EmptyVerifiedClaims tests with no verified claims
func TestGenerateIDToken_EmptyVerifiedClaims(t *testing.T) {
	ctx := context.Background()

	privateKey, err := generateTestRSAKey()
	assert.NoError(t, err)

	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				Issuer:      "https://example.com",
				SubjectType: "public",
				SubjectSalt: "salt",
			},
		},
	}

	log := logger.NewSimple("test-idtoken")
	tracer, _ := trace.NewForTesting(ctx, "test", log)

	client, _ := New(ctx, nil, cfg, tracer, log)
	client.oidcSigningKey = privateKey

	session := &db.Session{
		OIDCRequest: db.OIDCRequest{
			Nonce: "test-nonce",
		},
		OpenID4VP: db.OpenID4VPSession{
			WalletID: "wallet-1",
		},
		VerifiedClaims: map[string]any{}, // Empty claims
	}

	testClient := &db.Client{ClientID: "client-1"}

	tokenString, err := client.generateIDToken(session, testClient)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Parse token
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})

	claims := token.Claims.(jwt.MapClaims)

	// Should only have standard OIDC claims
	assert.Contains(t, claims, "iss")
	assert.Contains(t, claims, "sub")
	assert.Contains(t, claims, "aud")
	assert.Contains(t, claims, "exp")
	assert.Contains(t, claims, "iat")
	assert.Contains(t, claims, "nonce")

	// Should not have custom claims
	assert.NotContains(t, claims, "given_name")
	assert.NotContains(t, claims, "email")
}

// TestGenerateIDToken_ComplexClaims tests with various claim types
func TestGenerateIDToken_ComplexClaims(t *testing.T) {
	ctx := context.Background()

	privateKey, err := generateTestRSAKey()
	assert.NoError(t, err)

	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				Issuer:      "https://example.com",
				SubjectType: "public",
				SubjectSalt: "salt",
			},
		},
	}

	log := logger.NewSimple("test-idtoken")
	tracer, _ := trace.NewForTesting(ctx, "test", log)

	client, _ := New(ctx, nil, cfg, tracer, log)
	client.oidcSigningKey = privateKey

	session := &db.Session{
		OIDCRequest: db.OIDCRequest{
			Nonce: "test-nonce",
		},
		OpenID4VP: db.OpenID4VPSession{
			WalletID: "wallet-1",
		},
		VerifiedClaims: map[string]any{
			"name":           "John Doe",
			"email":          "john@example.com",
			"email_verified": true,
			"age":            30,
			"address": map[string]any{
				"street":  "123 Main St",
				"city":    "Springfield",
				"country": "US",
			},
			"roles": []string{"user", "admin"},
		},
	}

	testClient := &db.Client{ClientID: "client-1"}

	tokenString, err := client.generateIDToken(session, testClient)
	assert.NoError(t, err)

	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})

	claims := token.Claims.(jwt.MapClaims)

	// Verify complex claims are preserved
	assert.Equal(t, "John Doe", claims["name"])
	assert.Equal(t, "john@example.com", claims["email"])
	assert.Equal(t, true, claims["email_verified"])
	assert.Equal(t, float64(30), claims["age"]) // JSON numbers become float64

	// Verify nested object
	address, ok := claims["address"].(map[string]any)
	assert.True(t, ok, "Address should be a map")
	assert.Equal(t, "123 Main St", address["street"])
	assert.Equal(t, "Springfield", address["city"])

	// Verify array
	roles, ok := claims["roles"].([]any)
	assert.True(t, ok, "Roles should be an array")
	assert.Len(t, roles, 2)
}

// BenchmarkGenerateIDToken benchmarks ID token generation
func BenchmarkGenerateIDToken(b *testing.B) {
	ctx := context.Background()
	privateKey, _ := generateTestRSAKey()

	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				Issuer:      "https://example.com",
				SubjectType: "public",
				SubjectSalt: "salt",
			},
		},
	}

	log := logger.NewSimple("test-idtoken")
	tracer, _ := trace.NewForTesting(ctx, "test", log)

	client, _ := New(ctx, nil, cfg, tracer, log)
	client.oidcSigningKey = privateKey

	session := &db.Session{
		OIDCRequest: db.OIDCRequest{Nonce: "nonce"},
		OpenID4VP:   db.OpenID4VPSession{WalletID: "wallet"},
		VerifiedClaims: map[string]any{
			"name":  "John Doe",
			"email": "john@example.com",
		},
	}

	testClient := &db.Client{ClientID: "client-1"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.generateIDToken(session, testClient)
	}
}
