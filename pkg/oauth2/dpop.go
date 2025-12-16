package oauth2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"vc/internal/gen/issuer/apiv1_issuer"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type DPoP struct {
	// JTI Unique identifier for the DPoP proof JWT. The value MUST be assigned such that there is a negligible probability that the same value will be assigned to any other DPoP proof used in the same context during the time window of validity. Such uniqueness can be accomplished by encoding (base64url or any other suitable encoding) at least 96 bits of pseudorandom data or by using a version 4 Universally Unique Identifier (UUID) string according to [RFC4122]. The jti can be used by the server for replay detection and prevention; see Section 11.1.
	JTI string `json:"jti" validate:"required"`

	//HTM The value of the HTTP method (Section 9.1 of [RFC9110]) of the request to which the JWT is attached.¶
	HTM string `json:"htm" validate:"required,oneof=POST GET PUT DELETE PATCH OPTIONS HEAD"`

	// HTU The HTTP target URI (Section 7.1 of [RFC9110]) of the request to which the JWT is attached, without query and fragment parts.¶
	HTU string `json:"htu" validate:"required,url"`

	// IAT Creation timestamp of the JWT (Section 4.1.6 of [RFC7519]).¶
	//IAT int64 `json:"iat" validate:"required"` // TODO: use time.Time

	// ATH Hash of the access token. The value MUST be the result of a base64url encoding (as defined in Section 2 of [RFC7515]) the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's value.¶
	ATH string `json:"ath"`

	Thumbprint string `json:"thumbprint,omitempty"` // Optional, used for JWK thumbprint

	JWK *apiv1_issuer.Jwk `json:"jwk,omitempty"` // JWK claim, optional
}

func (d *DPoP) Unmarshal(claims jwt.MapClaims) error {
	// Unmarshal the claims into the DPoP struct
	data, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("failed to marshal claims: %w", err)
	}

	if err := json.Unmarshal(data, d); err != nil {
		return fmt.Errorf("failed to unmarshal claims into DPoP struct: %w", err)
	}

	return nil
}

func parseDpopJWK(jwkClaim []byte) (any, string, error) {
	keySet, err := jwk.Parse(jwkClaim)
	if err != nil {
		return nil, "", err
	}

	key, ok := keySet.Key(0)
	if !ok {
		return nil, "", fmt.Errorf("failed to get key from JWK set")
	}

	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get key fingerprint: %w", err)
	}
	fingerprint := fmt.Sprintf("%x", thumbprint)

	var kk = &ecdsa.PublicKey{}

	if err := jwk.Export(key, kk); err != nil {
		return nil, "", fmt.Errorf("failed to export key from JWK: %w", err)
	}

	if err := key.Validate(); err != nil {
		return nil, "", fmt.Errorf("failed to validate JWK: %w", err)
	}

	keyIsPrivate, err := jwk.IsPrivateKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("failed to check if key is private: %w", err)
	}
	if keyIsPrivate {
		fmt.Println("JWK is a private key, expected a public key")
	}

	return kk, fingerprint, err
}

func ValidateAndParseDPoPJWT(dPopJWT string) (*DPoP, error) {
	if dPopJWT == "" {
		return nil, fmt.Errorf("DPoP JWT is empty")
	}
	fmt.Println("Validating DPoP JWT")
	dpopClaims := &DPoP{}
	claims := jwt.MapClaims{}

	jwkClaim := map[string]any{}

	token, err := jwt.ParseWithClaims(dPopJWT, claims, func(token *jwt.Token) (any, error) {
		jwkHeader, jwkOk := token.Header["jwk"].(map[string]any)
		if !jwkOk {
			return nil, fmt.Errorf("jwk header not found or invalid type in token")
		}
		fmt.Println("JWK in token header:", jwkHeader)

		b, err := json.Marshal(jwkHeader)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal JWK: %w", err)
		}
		var signingKey any
		signingKey, dpopClaims.Thumbprint, err = parseDpopJWK(b)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JWK: %w", err)
		}

		if token.Header["typ"] != "dpop+jwt" {
			return nil, fmt.Errorf("unexpected token type: %v", token.Header["typ"])
		}

		// Use the already-checked jwkHeader
		jwkClaim = jwkHeader

		alg := token.Header["alg"]
		switch jwt.GetSigningMethod(alg.(string)).(type) {
		case *jwt.SigningMethodECDSA:
			return signingKey.(*ecdsa.PublicKey), nil
		case *jwt.SigningMethodRSA:
			return signingKey.(*rsa.PublicKey), nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", alg)
		}
	})
	if err != nil {
		return nil, jwt.ErrSignatureInvalid
	}

	if err := dpopClaims.Unmarshal(claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims into DPoP struct: %w", err)
	}

	jwkBytes, err := json.Marshal(jwkClaim) // Ensure the JWK is marshaled to JSON
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK: %w", err)
	}

	jwk := &apiv1_issuer.Jwk{}
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWK: %w", err)
	}

	jwk.KeyOps = []string{"verify"}
	jwk.Ext = true

	fmt.Println("Parsed DPoP JWT:", token, "valid:", token.Valid, "jwk", jwk)

	dpopClaims.JWK = jwk

	return dpopClaims, nil
}

func (c *DPoP) IsAccessTokenDPoP(token string) bool {
	// Check if the ATH is set, which indicates that this is a DPoP proof
	if c.ATH == token {
		return true
	}

	return false
}
