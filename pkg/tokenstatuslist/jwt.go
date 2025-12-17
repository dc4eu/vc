package tokenstatuslist

import (
	"crypto"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTTypHeader is the typ header value for Status List Token JWTs (Section 5.1)
const JWTTypHeader = "statuslist+jwt"

// JWTClaims represents the JWT claims for a Status List Token (Section 5.1)
// The JWT header MUST have typ: statuslist+jwt
type JWTClaims struct {
	jwt.RegisteredClaims

	// StatusList: REQUIRED. The status_list claim containing the Status List.
	StatusList StatusListClaim `json:"status_list"`

	// TTL: RECOMMENDED. Time to live in seconds - maximum time the token can be cached.
	TTL int64 `json:"ttl,omitempty"`
}

// JWTSigningConfig holds JWT-specific signing configuration.
type JWTSigningConfig struct {
	// SigningKey is the private key for signing (REQUIRED)
	SigningKey crypto.PrivateKey

	// SigningMethod is the JWT signing method (e.g., jwt.SigningMethodES256) (REQUIRED)
	SigningMethod jwt.SigningMethod
}

// JWTConfig holds JWT-specific configuration for generating a Status List Token.
// Deprecated: Use StatusList.GenerateJWT with JWTSigningConfig instead.
type JWTConfig struct {
	TokenConfig

	// SigningKey is the private key for signing (REQUIRED)
	SigningKey crypto.PrivateKey

	// SigningMethod is the JWT signing method (e.g., jwt.SigningMethodES256) (REQUIRED)
	SigningMethod jwt.SigningMethod
}

// GenerateJWT creates a signed Status List Token JWT per Section 5.1.
// The token includes:
// - Header: typ=statuslist+jwt, alg, kid
// - Claims: sub, iss, iat, exp (optional), ttl (optional), status_list
func (sl *StatusList) GenerateJWT(cfg JWTSigningConfig) (string, error) {
	// Validate required fields
	if cfg.SigningKey == nil {
		return "", fmt.Errorf("signing key is required")
	}
	if cfg.SigningMethod == nil {
		return "", fmt.Errorf("signing method is required")
	}

	// Compress and encode the status list
	lst, err := sl.CompressAndEncode()
	if err != nil {
		return "", fmt.Errorf("failed to compress status list: %w", err)
	}

	now := time.Now()

	// Build the claims
	claims := JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  sl.Subject,
			Issuer:   sl.Issuer,
			IssuedAt: jwt.NewNumericDate(now),
		},
		StatusList: StatusListClaim{
			Bits:           Bits,
			Lst:            lst,
			AggregationURI: sl.AggregationURI,
		},
	}

	// Add optional expiration
	if sl.ExpiresIn > 0 {
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(sl.ExpiresIn))
	}

	// Add optional TTL
	if sl.TTL > 0 {
		claims.TTL = sl.TTL
	}

	// Create the token with the required typ header
	token := jwt.NewWithClaims(cfg.SigningMethod, claims)

	// Set the typ header to statuslist+jwt as per Section 5.1
	token.Header["typ"] = JWTTypHeader

	// Set the key ID if provided
	if sl.KeyID != "" {
		token.Header["kid"] = sl.KeyID
	}

	// Sign the token
	signedToken, err := token.SignedString(cfg.SigningKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign status list token: %w", err)
	}

	return signedToken, nil
}

// GenerateJWT creates a signed Status List Token JWT per Section 5.1.
// Deprecated: Use StatusList.GenerateJWT instead.
func GenerateJWT(cfg JWTConfig) (string, error) {
	sl := &StatusList{
		statuses:       cfg.Statuses,
		Issuer:         cfg.Issuer,
		Subject:        cfg.Subject,
		TTL:            cfg.TTL,
		ExpiresIn:      cfg.ExpiresIn,
		KeyID:          cfg.KeyID,
		AggregationURI: cfg.AggregationURI,
	}
	return sl.GenerateJWT(JWTSigningConfig{
		SigningKey:    cfg.SigningKey,
		SigningMethod: cfg.SigningMethod,
	})
}

// ParseJWT parses a Status List Token JWT and returns the claims.
// It validates the token signature using the provided key function.
func ParseJWT(tokenString string, keyFunc jwt.Keyfunc) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse status list token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid status list token claims")
	}

	// Verify the typ header
	if typ, ok := token.Header["typ"].(string); !ok || typ != JWTTypHeader {
		return nil, fmt.Errorf("invalid typ header: expected %s", JWTTypHeader)
	}

	return claims, nil
}

// GetStatusFromJWT retrieves a status value from a parsed JWT Status List Token.
// The index corresponds to the "idx" value in the Referenced Token's status claim.
func GetStatusFromJWT(claims *JWTClaims, index int) (uint8, error) {
	// Decode and decompress the status list
	statuses, err := DecodeAndDecompress(claims.StatusList.Lst)
	if err != nil {
		return 0, fmt.Errorf("failed to decode status list: %w", err)
	}

	return GetStatus(statuses, index)
}
