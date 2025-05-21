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
	"net"
	"time"
	"vc/pkg/openid4vp"
)

type ClientMetadata struct { //From: OpenID Connect Dynamic Client Registration
	JWKS                              JWKS      `json:"jwks"`
	AuthorizationEncryptedResponseAlg string    `json:"authorization_encrypted_response_alg,omitempty"`
	AuthorizationEncryptedResponseEnc string    `json:"authorization_encrypted_response_enc,omitempty"`
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

func BuildClientMetadataFromECDSAKey(privateEmpKey *ecdsa.PrivateKey, encryptDirectPostJWT bool) (*ClientMetadata, error) {
	curve := privateEmpKey.Curve
	curveSize := (curve.Params().BitSize + 7) / 8
	x := bigIntToBase64URL(privateEmpKey.PublicKey.X, curveSize)
	y := bigIntToBase64URL(privateEmpKey.PublicKey.Y, curveSize)

	jwk := JWK{
		Kty: "EC",
		Use: "enc",
		Kid: uuid.NewString(), //Only for emp keys
		Crv: getCurveName(privateEmpKey),
		X:   x,
		Y:   y,
		Alg: "ECDH-ES",
	}

	clientMetadata := &ClientMetadata{
		JWKS: JWKS{
			Keys: []JWK{jwk},
		},
		VPFormats: VPFormats{
			VCSDJWT: VCSDJWT{
				SDJWTAlgValues: []string{"ES256"},
				KBJWTAlgValues: []string{"ES256"},
			},
		},
	}
	if encryptDirectPostJWT {
		clientMetadata.AuthorizationEncryptedResponseAlg = "ECDH-ES"
		clientMetadata.AuthorizationEncryptedResponseEnc = "A256GCM"
	}

	return clientMetadata, nil
}

func getCurveName(priv *ecdsa.PrivateKey) string {
	switch priv.Curve {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return "unknown"
	}
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

func GenerateSelfSignedX509Cert(privateKey *ecdsa.PrivateKey) (*openid4vp.CertData, error) {
	//x509_san_dns

	//TODO: CONFIG - LÄS IN

	subject := pkix.Name{
		Country:      []string{"SE"},
		Organization: []string{"SUNET"},
		Locality:     []string{"Stockholm"},
		SerialNumber: uuid.NewString(),
		CommonName:   "vc-interop-1.sunet.se", //TODO: normalt samma som DNSNames[0]
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
		DNSNames: []string{
			"vc-interop-1.sunet.se",
			"vc-interop-2.sunet.se",
			"satosa-test-1.sunet.se",
			"satosa-test-2.sunet.se",
			"satosa-dev-1.sunet.se",
			"satosa-dev-2.sunet.se"}, //TODO vad ska dns names sättas till; vc-interop-1.sunet.se OR vc-interop-2.sunet.se ?
		IPAddresses: []net.IP{ //TODO: läs in som properties
			net.ParseIP("172.16.50.24"), //TODO: specialare för att kanske få det att fungera med bara ip-adress i utvecklings/testmiljöer (men verkar inte räknas till x509_san_dns utan x509_san_ip)?
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return &openid4vp.CertData{
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
