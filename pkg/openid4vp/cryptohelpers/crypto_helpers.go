package cryptohelpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/google/uuid"
	"math/big"
	"time"
)

type ClientMetadata struct { //From: OpenID Connect Dynamic Client Registration
	JWKS                              JWKS      `json:"jwks"`
	AuthorizationEncryptedResponseAlg string    `json:"authorization_encrypted_response_alg"`
	AuthorizationEncryptedResponseEnc string    `json:"authorization_encrypted_response_enc"`
	VPFormats                         VPFormats `json:"vp_formats"`
}

type JWKS struct { //From: RFC 7517 (JWK)
	Keys []JWK `json:"keys"`
}

type VPFormats struct {
	VCSDJWT VCSDJWT `json:"vc+sd-jwt"`
}

type VCSDJWT struct {
	SDJWTAlgValues []string `json:"sd-jwt_alg_values"`
	KBJWTAlgValues []string `json:"kb-jwt_alg_values"`
}

func BuildClientMetadataFromECDSAKey(privateEmpKey *ecdsa.PrivateKey) (*ClientMetadata, error) {
	//TODO: gör denna mer generisk samt bryt ev metadata till annan del av koden men behåll jwks här
	crv := "P-256"
	curveSize := 32 // byte-length for P-256
	x := bigIntToBase64URL(privateEmpKey.X, curveSize)
	y := bigIntToBase64URL(privateEmpKey.Y, curveSize)

	jwk := JWK{
		Kty: "EC",
		Use: "enc",
		Kid: uuid.NewString(), //Only for emp keys
		Crv: crv,
		X:   x,
		Y:   y,
	}

	clientMetadata := &ClientMetadata{
		JWKS: JWKS{
			Keys: []JWK{jwk},
		},
		AuthorizationEncryptedResponseAlg: "ECDH-ES",
		AuthorizationEncryptedResponseEnc: "A256GCM",
		VPFormats: VPFormats{
			VCSDJWT: VCSDJWT{
				SDJWTAlgValues: []string{"ES256"},
				KBJWTAlgValues: []string{"ES256"},
			},
		},
	}

	return clientMetadata, nil
}

func base64urlNoPad(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func bigIntToBase64URL(i *big.Int, size int) string {
	bytes := i.FillBytes(make([]byte, size))
	return base64urlNoPad(bytes)
}

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
