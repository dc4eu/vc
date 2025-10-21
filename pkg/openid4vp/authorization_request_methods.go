package openid4vp

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

// Sign signs the jwt
func (authorizationRequest *RequestObject) Sign(signingMethod jwt.SigningMethod, signingKey any, x5c []string) (string, error) {
	header := map[string]any{
		"alg": signingMethod.Alg(),
		"typ": "oauth-authz-req+jwt",
		"x5c": x5c,
	}

	data, err := json.Marshal(authorizationRequest)
	if err != nil {
		return "", err
	}
	body := jwt.MapClaims{}
	if err := json.Unmarshal(data, &body); err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(signingMethod, body)
	token.Header = header

	signedJWT, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return signedJWT, nil
}
