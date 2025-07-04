package pki

import (
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func PEM2jwk(pemKey []byte) (jwk.Key, error) {
	// Convert PEM to JWK
	jwkKey, err := jwk.ParseKey(pemKey, jwk.WithPEM(true))
	if err != nil {
		return nil, err
	}
	return jwkKey, nil
}
