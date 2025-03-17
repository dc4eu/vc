package cryptohelpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"github.com/google/uuid"
	"math/big"
	"time"
)

func GenerateECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	if privateKey.D.Sign() <= 0 {
		return nil, errors.New("generated private key is invalid")
	}

	return privateKey, nil
}

func GenerateSelfSignedX509CertDER(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	subject := pkix.Name{
		Country:      []string{"SE"},
		Organization: []string{"SUNET"},
		Locality:     []string{"Stockholm"},
		SerialNumber: uuid.NewString(),
		CommonName:   "vcverifier.sunet.se",
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		DNSNames:     []string{"vcverifier.sunet.se"}, //TODO vad ska dns names sättas till?
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(4383 * time.Hour),                             //~6 months
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, //TODO: vad ska KeyUsage sättas till?
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},               //TODO: vad ska ExtKeyUsage sättas till?
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return certDER, nil
}

func generateSerialNumber() (*big.Int, error) {
	u := uuid.New()
	uBytes, err := u.MarshalBinary()
	if err != nil {
		return nil, err
	}

	serialNumber := new(big.Int).SetBytes(uBytes)
	return serialNumber, nil
}
