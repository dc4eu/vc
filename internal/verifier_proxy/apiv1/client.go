package apiv1

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"
	"vc/internal/verifier_proxy/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vp"
	"vc/pkg/trace"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Client holds the verifier proxy API implementation
type Client struct {
	cfg                         *model.Cfg
	db                          *db.Service
	log                         *logger.Log
	tracer                      *trace.Tracer
	oidcSigningKey              any
	oidcSigningAlg              string
	ephemeralEncryptionKeyCache *ttlcache.Cache[string, jwk.Key]
	requestObjectCache          *ttlcache.Cache[string, *openid4vp.RequestObject]
}

// New creates a new instance of the verifier proxy API
func New(ctx context.Context, db *db.Service, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:                         cfg,
		db:                          db,
		log:                         log.New("apiv1"),
		tracer:                      tracer,
		ephemeralEncryptionKeyCache: ttlcache.New(ttlcache.WithTTL[string, jwk.Key](10 * time.Minute)),
		requestObjectCache:          ttlcache.New(ttlcache.WithTTL[string, *openid4vp.RequestObject](5 * time.Minute)),
	}

	// Start caches
	go c.ephemeralEncryptionKeyCache.Start()
	go c.requestObjectCache.Start()

	// Load OIDC signing key
	// TODO: Load from config path
	c.oidcSigningAlg = "RS256"

	c.log.Info("Started")

	return c, nil
}

// generateSessionID creates a cryptographically random session identifier
func (c *Client) generateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback to time-based ID if random fails
		return oauth2.GenerateCryptographicNonceFixedLength(32)
	}
	return hex.EncodeToString(b)
}

// generateAuthorizationCode creates a cryptographically random authorization code
func (c *Client) generateAuthorizationCode() string {
	return oauth2.GenerateCryptographicNonceFixedLength(32)
}

// generateAccessToken creates a cryptographically random access token
func (c *Client) generateAccessToken() string {
	return oauth2.GenerateCryptographicNonceFixedLength(32)
}

// generateRefreshToken creates a cryptographically random refresh token
func (c *Client) generateRefreshToken() string {
	return oauth2.GenerateCryptographicNonceFixedLength(32)
}

// generateSubjectIdentifier creates a subject identifier for the user
// This can be either public (same across all RPs) or pairwise (different per RP)
func (c *Client) generateSubjectIdentifier(walletID string, clientID string) string {
	subjectType := c.cfg.VerifierProxy.OIDC.SubjectType

	switch subjectType {
	case "pairwise":
		// Generate pairwise pseudonymous identifier
		hash := sha256.New()
		hash.Write([]byte(walletID))
		hash.Write([]byte(clientID))
		hash.Write([]byte(c.cfg.VerifierProxy.OIDC.SubjectSalt))
		return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	default:
		// Public subject identifier (same across all RPs)
		hash := sha256.New()
		hash.Write([]byte(walletID))
		hash.Write([]byte(c.cfg.VerifierProxy.OIDC.SubjectSalt))
		return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	}
}

// EphemeralEncryptionKey generates or retrieves an ephemeral encryption key
// TODO: Implement when needed for encrypted responses
/* func (c *Client) EphemeralEncryptionKey(kid string) (jwk.Key, jwk.Key, error) {
	// Check cache first
	if item := c.ephemeralEncryptionKeyCache.Get(kid); item != nil {
		privateKey := item.Value()
		publicKey, err := privateKey.PublicKey()
		if err != nil {
			return nil, nil, err
		}
		return privateKey, publicKey, nil
	}

	// Generate new key pair
	privateKey, err := jwk.GenerateKey(jwk.EC, jwk.P256, jwk.WithKeyID(kid))
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := privateKey.PublicKey()
	if err != nil {
		return nil, nil, err
	}

	// Cache the key
	c.ephemeralEncryptionKeyCache.Set(kid, privateKey, ttlcache.DefaultTTL)

	return privateKey, publicKey, nil
}
*/
