package jwthelpers

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"vc/pkg/openid4vp"
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
	//TODO: add "client_metadata"?
}

func CreateAndSignJWS(privateKey interface{}, signingMethod jwt.SigningMethod, x5cCertDERBase64 string, claims *CustomClaims) (string, error) {
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
