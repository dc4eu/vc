package apiv1

import (
	"context"
	"testing"
	"time"
	"vc/internal/verifier_proxy/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/stretchr/testify/assert"
)

// TestNew tests the Client constructor
func TestNew(t *testing.T) {
	ctx := context.Background()

	// Create minimal configuration
	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				Issuer:      "https://example.com",
				SubjectType: "public",
				SubjectSalt: "test-salt",
			},
		},
	}

	// Create logger
	log, err := logger.New("test-client", "", false)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create tracer for testing
	tracer, err := trace.NewForTesting(ctx, "test", log)
	if err != nil {
		t.Fatalf("Failed to create tracer: %v", err)
	}

	// Create mock database service
	dbService := &db.Service{
		// Note: db.Service fields are not exported, so we can't initialize them
		// This is acceptable for this test as New() doesn't interact with db yet
	}

	// Test successful creation
	client, err := New(ctx, dbService, cfg, tracer, log)
	assert.NoError(t, err)
	assert.NotNil(t, client)

	// Verify client fields are initialized
	assert.NotNil(t, client.cfg, "Config should be set")
	assert.NotNil(t, client.db, "Database service should be set")
	assert.NotNil(t, client.log, "Logger should be set")
	assert.NotNil(t, client.tracer, "Tracer should be set")
	assert.NotNil(t, client.ephemeralEncryptionKeyCache, "Encryption key cache should be initialized")
	assert.NotNil(t, client.requestObjectCache, "Request object cache should be initialized")
	assert.Equal(t, "RS256", client.oidcSigningAlg, "Default signing algorithm should be RS256")

	// Give caches a moment to start (they're started in goroutines)
	time.Sleep(10 * time.Millisecond)

	// Verify the client holds the correct references
	assert.Equal(t, cfg, client.cfg)
	assert.Equal(t, dbService, client.db)
	assert.Equal(t, tracer, client.tracer)
}

// TestNew_CacheInitialization tests that caches are properly initialized with TTLs
func TestNew_CacheInitialization(t *testing.T) {
	ctx := context.Background()
	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				Issuer:      "https://example.com",
				SubjectType: "public",
				SubjectSalt: "test-salt",
			},
		},
	}
	log, _ := logger.New("test-client", "", false)
	tracer, _ := trace.NewForTesting(ctx, "test", log)
	dbService := &db.Service{}

	client, err := New(ctx, dbService, cfg, tracer, log)
	assert.NoError(t, err)

	// Verify caches are not nil
	assert.NotNil(t, client.ephemeralEncryptionKeyCache)
	assert.NotNil(t, client.requestObjectCache)

	// Note: We can't directly test TTL values as they're internal to ttlcache,
	// but we can verify the caches work
	time.Sleep(10 * time.Millisecond) // Let cache goroutines start
}

// TestNew_LoggerScoping tests that the logger is properly scoped
func TestNew_LoggerScoping(t *testing.T) {
	ctx := context.Background()
	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				Issuer:      "https://example.com",
				SubjectType: "public",
				SubjectSalt: "test-salt",
			},
		},
	}

	log, _ := logger.New("test-client", "", false)
	originalLogger := log

	tracer, _ := trace.NewForTesting(ctx, "test", log)
	dbService := &db.Service{}

	client, err := New(ctx, dbService, cfg, tracer, log)
	assert.NoError(t, err)

	// The logger should be scoped with "apiv1"
	assert.NotNil(t, client.log)
	// Note: We can't directly test the scope name, but we verify it's not the same instance
	// The New("apiv1") call creates a new logger instance
	assert.NotEqual(t, originalLogger, client.log, "Logger should be a new scoped instance")
}

// BenchmarkNew benchmarks the Client constructor
func BenchmarkNew(b *testing.B) {
	ctx := context.Background()
	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				Issuer:      "https://example.com",
				SubjectType: "public",
				SubjectSalt: "test-salt",
			},
		},
	}
	log, _ := logger.New("test-client", "", false)
	tracer, _ := trace.NewForTesting(ctx, "test", log)
	dbService := &db.Service{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, err := New(ctx, dbService, cfg, tracer, log)
		if err != nil {
			b.Fatal(err)
		}
		_ = client
	}
}
