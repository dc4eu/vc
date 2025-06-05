package openid4vp

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/json"
	"github.com/lestrrat-go/jwx/jwk"
)

type TrustService struct {
}

func (ts *TrustService) ExtractPublicKeyFromCnfMap(cnf map[string]interface{}) (interface{}, error) {
	jwkMap, ok := cnf["jwk"]
	if !ok {
		return nil, fmt.Errorf("missing 'jwk' field in cnf")
	}

	jwkJSON, err := json.Marshal(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal jwk to JSON: %w", err)
	}

	var jwk jose.JSONWebKey
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWK: %w", err)
	}

	if !jwk.Valid() {
		return nil, fmt.Errorf("invalid JWK")
	}

	return jwk.Key, nil
}

func (ts *TrustService) ExtractPublicKeyFromX5C(x5cBase64 string) (interface{}, error) {
	derCert, err := base64.StdEncoding.DecodeString(x5cBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 x5c certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.PublicKey, nil
}

func (ts *TrustService) FetchPublicKeyFromJWKS(jwksURL string, kid string) (crypto.PublicKey, error) {
	set, err := jwk.Fetch(context.Background(), jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	key, found := set.LookupKeyID(kid)
	if !found {
		return nil, fmt.Errorf("no key found for kid: %s", kid)
	}

	var pubkey crypto.PublicKey
	if err := key.Raw(&pubkey); err != nil {
		return nil, fmt.Errorf("failed to get raw public key: %w", err)
	}

	return pubkey, nil
}
