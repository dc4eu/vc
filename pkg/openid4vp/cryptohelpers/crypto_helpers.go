package cryptohelpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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

type CertData struct {
	CertDER []byte
	CertPEM []byte
}

func GenerateSelfSignedX509Cert(privateKey *ecdsa.PrivateKey) (*CertData, error) {
	//x509_san_dns

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

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              now.Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement, //TODO: vad ska KeyUsage sättas till?
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},                                           //TODO: vad ska ExtKeyUsage sättas till?
		BasicConstraintsValid: true,
		DNSNames:              []string{"vcverifier.sunet.se"}, //TODO vad ska dns names sättas till?
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return &CertData{
		CertDER: certDER,
		CertPEM: certPEM,
	}, nil
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
