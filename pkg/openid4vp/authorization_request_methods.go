package openid4vp

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

func (a *AuthorizationRequest_v2) MarshalJson() ([]byte, error) {
	bJSON, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}

	return bJSON, nil
}

func (a *AuthorizationRequest_v2) MarshalMap() (map[string]any, error) {
	bJSON, err := a.MarshalJson()
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(bJSON, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// Sign signs the jwt
func (a *AuthorizationRequest_v2) Sign(signingMethod jwt.SigningMethod, signingKey any, x5c []string) (string, error) {
	header := map[string]any{
		"alg": signingMethod.Alg(),
		"typ": "oauth-authz-req+jwt",
		"x5c": x5c,
	}

	data, err := json.Marshal(a)
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
