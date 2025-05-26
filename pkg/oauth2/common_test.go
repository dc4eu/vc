package oauth2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var nonRandom = bytes.NewReader([]byte("01234567890123456789012345678901234567890123456789ABCDEF"))

// mockGenerateECDSAKey generates a mock ECDSA key and a self-signed base65 encoded certificate
func mockGenerateECDSAKey(t *testing.T) (crypto.PrivateKey, string) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), nonRandom)
	assert.NoError(t, err)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"SUNET"},
			Country:       []string{"SE"},
			Province:      []string{""},
			Locality:      []string{"Stockholm"},
			StreetAddress: []string{"Tulegatan 11"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
	assert.NoError(t, err)

	//reply := base64.RawURLEncoding.EncodeToString(caBytes)
	reply := base64.RawStdEncoding.EncodeToString(caBytes)

	return privateKey, reply
}
