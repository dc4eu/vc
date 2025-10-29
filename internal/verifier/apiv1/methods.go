package apiv1

import (
	"crypto/ecdh"
	"crypto/rand"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// EphemeralEncryptionKey generates a new ephemeral encryption key pair and store them in a cache, return private and public JWKs, or error
func (c *Client) EphemeralEncryptionKey(kid string) (jwk.Key, jwk.Key, error) {
	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privateJWK, err := jwk.Import(privKey)
	if err != nil {
		return nil, nil, err
	}
	if err := privateJWK.Set("kid", kid); err != nil {
		return nil, nil, err
	}

	c.ephemeralEncryptionKeyCache.Set(kid, privateJWK, ttlcache.DefaultTTL)

	pub := privKey.Public()

	publicJWK, err := jwk.Import(pub)
	if err != nil {
		return nil, nil, err
	}

	if err := publicJWK.Set("use", "enc"); err != nil {
		return nil, nil, err
	}

	if err := publicJWK.Set("kid", kid); err != nil {
		return nil, nil, err
	}

	return privateJWK, publicJWK, nil
}
