package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/bcrypt"

	"vc/internal/verifier_proxy/apiv1"
	"vc/internal/verifier_proxy/db"
	"vc/internal/verifier_proxy/httpserver"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"
)

// IntegrationSuite provides the test infrastructure for integration tests
type IntegrationSuite struct {
	t *testing.T

	// Context
	ctx    context.Context
	cancel context.CancelFunc

	// Configuration
	cfg *model.Cfg

	// Services
	db         *db.Service
	apiv1      *apiv1.Client
	httpServer *httpserver.Service
	testServer *httptest.Server

	// Test helpers
	log    *logger.Log
	tracer *trace.Tracer

	// Testcontainers
	mongoContainer testcontainers.Container

	// Test data
	testClients map[string]*db.Client
}

// NewIntegrationSuite creates a new integration test suite
func NewIntegrationSuite(t *testing.T) *IntegrationSuite {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second) // Increased for container startup

	suite := &IntegrationSuite{
		t:           t,
		ctx:         ctx,
		cancel:      cancel,
		testClients: make(map[string]*db.Client),
	}

	suite.initializeConfiguration()
	suite.startMongoContainer()
	suite.initializeLogging()
	suite.initializeTracing()
	suite.initializeDatabase()
	suite.initializeServices()
	suite.bootstrapTestData()

	return suite
}

// initializeConfiguration creates test configuration
func (s *IntegrationSuite) initializeConfiguration() {
	s.cfg = &model.Cfg{
		Common: model.Common{
			Production: false,
			Log: model.Log{
				FolderPath: "",
			},
			Mongo: model.Mongo{
				URI: "", // Will be set after MongoDB container starts
			},
			Tracing: model.OTEL{
				Addr:    "localhost:4317",
				Type:    "grpc",
				Timeout: 10,
			},
		},
		VerifierProxy: model.VerifierProxy{
			APIServer: model.APIServer{
				Addr: "localhost:0", // Random port
				TLS: model.TLS{
					Enabled: false,
				},
			},
			ExternalURL: "http://localhost:8080",
			OIDC: model.OIDCConfig{
				Issuer:               "http://localhost:8080",
				SigningKeyPath:       "",
				SigningAlg:           "RS256",
				SessionDuration:      1800,  // 30 minutes
				CodeDuration:         600,   // 10 minutes
				AccessTokenDuration:  3600,  // 1 hour
				IDTokenDuration:      3600,  // 1 hour
				RefreshTokenDuration: 86400, // 24 hours
				SubjectType:          "pairwise",
				SubjectSalt:          "test-salt-change-in-production",
			},
			OpenID4VP: model.OpenID4VPConfig{
				PresentationTimeout: 300, // 5 minutes
				SupportedCredentials: []model.SupportedCredentialConfig{
					{
						VCT:    "eu.europa.ec.eudi.pid.1",
						Scopes: []string{"openid", "pid"},
					},
				},
			},
		},
	}
}

// startMongoContainer starts a MongoDB container using testcontainers
func (s *IntegrationSuite) startMongoContainer() {
	req := testcontainers.ContainerRequest{
		Image:        "mongo:7",
		ExposedPorts: []string{"27017/tcp"},
		WaitingFor:   wait.ForLog("Waiting for connections"),
	}

	var err error
	s.mongoContainer, err = testcontainers.GenericContainer(s.ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		s.t.Fatalf("Failed to start MongoDB container: %v", err)
	}

	// Get the mapped port
	mappedPort, err := s.mongoContainer.MappedPort(s.ctx, "27017")
	if err != nil {
		s.t.Fatalf("Failed to get mapped port: %v", err)
	}

	host, err := s.mongoContainer.Host(s.ctx)
	if err != nil {
		s.t.Fatalf("Failed to get container host: %v", err)
	}

	// Update configuration with MongoDB URI
	s.cfg.Common.Mongo.URI = fmt.Sprintf("mongodb://%s:%s", host, mappedPort.Port())
	s.t.Logf("MongoDB container started at %s", s.cfg.Common.Mongo.URI)
}

// initializeLogging creates test logger
func (s *IntegrationSuite) initializeLogging() {
	var err error
	s.log, err = logger.New("integration-test", "", false)
	if err != nil {
		s.t.Fatalf("Failed to create logger: %v", err)
	}
}

// initializeTracing creates test tracer
func (s *IntegrationSuite) initializeTracing() {
	var err error
	s.tracer, err = trace.New(s.ctx, s.cfg, "integration-test", s.log)
	if err != nil {
		s.t.Fatalf("Failed to create tracer: %v", err)
	}
}

// initializeDatabase creates mock database service
func (s *IntegrationSuite) initializeDatabase() {
	var err error
	s.db, err = db.New(s.ctx, s.cfg, s.tracer, s.log)
	if err != nil {
		s.t.Fatalf("Failed to create database service: %v", err)
	}
}

// initializeServices creates and starts the verifier proxy services
func (s *IntegrationSuite) initializeServices() {
	var err error

	// Create API client
	s.apiv1, err = apiv1.New(s.ctx, s.db, s.cfg, s.tracer, s.log)
	if err != nil {
		s.t.Fatalf("Failed to create API client: %v", err)
	}

	// Generate and set RSA signing key for OIDC tokens
	// (Production code has TODO for loading key from config)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s.t.Fatalf("Failed to generate RSA key: %v", err)
	}
	s.apiv1.SetSigningKeyForTesting(privateKey, "RS256")

	s.t.Log("API services initialized with test RSA key")
}

// bootstrapTestData loads test clients into the database
func (s *IntegrationSuite) bootstrapTestData() {
	// Register a confidential client with client_secret
	confidentialClient := s.registerClient(
		"test-confidential-client",
		"secret", // Will be hashed
		[]string{"http://localhost:3000/callback"},
		[]string{"authorization_code", "refresh_token"},
		[]string{"code"},
		[]string{"openid", "profile", "pid"},
		"client_secret_basic",
		true, // require_pkce
	)
	s.testClients["confidential"] = confidentialClient

	// Register a public client (no secret)
	publicClient := s.registerClient(
		"test-public-client",
		"", // No secret
		[]string{"http://localhost:3001/callback"},
		[]string{"authorization_code"},
		[]string{"code"},
		[]string{"openid", "pid"},
		"none",
		true, // require_pkce
	)
	s.testClients["public"] = publicClient
}

// registerClient creates and registers a test client
func (s *IntegrationSuite) registerClient(
	clientID string,
	clientSecret string,
	redirectURIs []string,
	grantTypes []string,
	responseTypes []string,
	allowedScopes []string,
	authMethod string,
	requirePKCE bool,
) *db.Client {
	client := &db.Client{
		ClientID:                clientID,
		RedirectURIs:            redirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: authMethod,
		AllowedScopes:           allowedScopes,
		SubjectType:             "pairwise",
		RequirePKCE:             requirePKCE,
	}

	// Hash client secret if provided
	if clientSecret != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			s.t.Fatalf("Failed to hash client secret: %v", err)
		}
		client.ClientSecretHash = string(hash)
	}

	// Store in mock database
	err := s.db.Clients.Create(s.ctx, client)
	if err != nil {
		s.t.Fatalf("Failed to register client: %v", err)
	}

	return client
}

// Cleanup tears down the test suite
func (s *IntegrationSuite) Cleanup() {
	if s.testServer != nil {
		s.testServer.Close()
	}
	if s.httpServer != nil {
		s.httpServer.Close(s.ctx)
	}
	if s.db != nil {
		s.db.Close(s.ctx)
	}
	if s.mongoContainer != nil {
		s.mongoContainer.Terminate(s.ctx)
	}
	if s.tracer != nil {
		s.tracer.Shutdown(s.ctx)
	}
	s.cancel()
}

// Helper functions

// generateRandomString generates a random hex string of given length
func generateRandomString(length int) string {
	bytes := make([]byte, length/2)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateTestRSAKey generates a test RSA key pair
func generateTestRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// GetHTTPClient returns an HTTP client for making requests
func (s *IntegrationSuite) GetHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects automatically
			return http.ErrUseLastResponse
		},
	}
}
