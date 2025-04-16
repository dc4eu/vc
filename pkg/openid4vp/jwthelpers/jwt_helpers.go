package jwthelpers

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"vc/pkg/openid4vp"
	"vc/pkg/openid4vp/cryptohelpers"
)

type CustomClaims struct {
	jwt.RegisteredClaims
	ResponseURI            string                            `json:"response_uri"`
	ClientIdScheme         string                            `json:"client_id_scheme"`
	ClientId               string                            `json:"client_id"`
	ResponseType           string                            `json:"response_type"`
	ResponseMode           string                            `json:"response_mode"`
	State                  string                            `json:"state"`
	Nonce                  string                            `json:"nonce"`
	PresentationDefinition *openid4vp.PresentationDefinition `json:"presentation_definition,omitempty"`
	ClientMetadata         *cryptohelpers.ClientMetadata     `json:"client_metadata,omitempty"`
}

func CreateAndSignJWS(privateKey interface{}, signingMethod jwt.SigningMethod, x5cCertDERBase64 string, claims *CustomClaims) (string, error) {
	if privateKey == nil {
		return "", errors.New("private key is nil")
	}
	if signingMethod == nil {
		return "", errors.New("signing method is nil")
	}
	if claims == nil {
		return "", errors.New("claims is nil")
	}
	token := jwt.NewWithClaims(signingMethod, claims)
	if x5cCertDERBase64 != "" {
		token.Header["x5c"] = []string{x5cCertDERBase64}
	}
	return token.SignedString(privateKey)
}

func GenerateNonce() string {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		return uuid.NewString()
	}
	return base64.RawURLEncoding.EncodeToString(nonce)
}
