package apiv1

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"vc/pkg/openid4vp"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func dummyPKCS8KeyParser(t *testing.T, path string) *rsa.PrivateKey {
	d, err := os.ReadFile(path)
	assert.NoError(t, err)

	block, _ := pem.Decode(d)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	assert.NoError(t, err)

	return parsed.(*rsa.PrivateKey)
}

func dummyPKCS1KeyParser(t *testing.T, path string) *rsa.PrivateKey {
	d, err := os.ReadFile(path)
	assert.NoError(t, err)

	block, _ := pem.Decode(d)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, err)

	return key
}

func TestLoadKeyPairFromPEMFile(t *testing.T) {
	tts := []struct {
		name        string
		want        *openid4vp.KeyPair
		keyType     string
		pkcsVersion string
		bitLength   int
	}{
		{
			name:        "RSA-pkcs1-2048",
			keyType:     "rsa",
			bitLength:   2048,
			pkcsVersion: "pkcs1",
			want: &openid4vp.KeyPair{
				KeyType:            openid4vp.KeyTypeRSA,
				PrivateKey:         nil,
				PublicKey:          nil,
				SigningMethodToUse: jwt.SigningMethodRS256,
			},
		},
		{
			name:        "RSA-pkcs8-2048",
			keyType:     "rsa",
			bitLength:   2048,
			pkcsVersion: "pkcs8",
			want: &openid4vp.KeyPair{
				KeyType:            openid4vp.KeyTypeRSA,
				PrivateKey:         nil,
				PublicKey:          nil,
				SigningMethodToUse: jwt.SigningMethodRS256,
			},
		},
		{
			name:        "RSA-pkcs8-4096",
			keyType:     "rsa",
			bitLength:   4096,
			pkcsVersion: "pkcs8",
			want: &openid4vp.KeyPair{
				KeyType:            openid4vp.KeyTypeRSA,
				PrivateKey:         nil,
				PublicKey:          nil,
				SigningMethodToUse: jwt.SigningMethodRS256,
			},
		},
		{
			name:        "RSA-pkcs1-4096",
			keyType:     "rsa",
			bitLength:   4096,
			pkcsVersion: "pkcs1",
			want: &openid4vp.KeyPair{
				KeyType:            openid4vp.KeyTypeRSA,
				PrivateKey:         nil,
				PublicKey:          nil,
				SigningMethodToUse: jwt.SigningMethodRS256,
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			fileName := fmt.Sprintf("%s_%d_key_%s.pem", tt.keyType, tt.bitLength, tt.pkcsVersion)
			keyFilePath := filepath.Join("../../../internal/verifier/apiv1/testdata/", fileName)
			got, err := LoadKeyPairFromPEMFile(keyFilePath)
			assert.NoError(t, err)

			switch tt.keyType {
			case "rsa":
				switch tt.pkcsVersion {
				case "pkcs1":
					tt.want.PrivateKey = dummyPKCS1KeyParser(t, keyFilePath)
					tt.want.PublicKey = &tt.want.PrivateKey.(*rsa.PrivateKey).PublicKey
				case "pkcs8":
					tt.want.PrivateKey = dummyPKCS8KeyParser(t, keyFilePath)
					tt.want.PublicKey = &tt.want.PrivateKey.(*rsa.PrivateKey).PublicKey
				}
			case "ec":
				t.Log("Not implemented yet")
			default:
				t.Fatalf("unsupported key type: %s", tt.keyType)
			}

			assert.Equal(t, tt.want, got)

		})
	}
}
