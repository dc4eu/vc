package jose

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

// JWK is a JSON Web Key
type JWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

// ParseSigningKey parses the private key from the file
func ParseSigningKey(signingKeyPath string) (*ecdsa.PrivateKey, error) {
	keyByte, err := os.ReadFile(signingKeyPath)
	if err != nil {
		return nil, err
	}
	if keyByte == nil {
		return nil, errors.New("private key missing")
	}

	privateKey, err := jwt.ParseECPrivateKeyFromPEM(keyByte)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// CreateJWK creates a JWK from the signing key
func CreateJWK(signingKeyPath string) (*JWK, *ecdsa.PrivateKey, error) {
	privateKey, err := ParseSigningKey(signingKeyPath)
	if err != nil {
		return nil, nil, err
	}

	//publicKey := &privateKey.PublicKey

	key, err := jwk.New(privateKey)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	m, err := key.AsMap(ctx)
	if err != nil {
		return nil, nil, err
	}
	jwk := &JWK{}
	for k, v := range m {
		switch k {
		case "x":
			jwk.X = base64.RawStdEncoding.EncodeToString(v.([]byte))
		case "y":
			jwk.Y = base64.RawStdEncoding.EncodeToString(v.([]byte))
		case "d":
			jwk.D = base64.RawStdEncoding.EncodeToString(v.([]byte))
		case "crv":
			jwk.CRV = v.(jwa.EllipticCurveAlgorithm).String()
		case "kty":
			jwk.KTY = v.(jwa.KeyType).String()
		default:
			return nil, nil, errors.New("unknown attribute in JWK")
		}

	}

	return jwk, privateKey, nil
}
