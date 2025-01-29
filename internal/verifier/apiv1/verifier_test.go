package apiv1

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto" // For secp256k1 (ES256K)
	"github.com/golang-jwt/jwt/v5"
	"testing"
	"time"
)

func TestVPToken_Validate(t *testing.T) {

	ecdsaP256Private, ecdsaP256Public, err := generateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	vp_token, err := build_vp_jws_token_with_ldp_vc_credentials(jwt.SigningMethodES256, ecdsaP256Private, "did:example:issuer#key-1")
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		RawToken string
		//ValidationResults map[string]bool
	}
	tests := []struct {
		name            string
		fields          fields
		holderPublicKey interface{}
		wantErr         bool
	}{
		//TODO bryt ut till till en testcase builder för att enkelt testa massa olika varianter
		{
			name: "Generated vp token",
			fields: fields{
				RawToken: vp_token,
			},
			holderPublicKey: ecdsaP256Public,
			wantErr:         false,
		},
		//{
		//	name: "Hardcoded vp_token_1",
		//	fields: fields{
		//		RawToken: `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUuY29tIiwiaXNzIjoiaHR0cHM6Ly93YWxsZXQuZXhhbXBsZS5jb20iLCJpYXQiOjE3MzgwNjU4OTksImV4cCI6MTczODE1MjI5OSwibm9uY2UiOiJyYW5kb21seS1nZW5lcmF0ZWQtbm9uY2UiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy9leGFtcGxlcy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlt7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJnaXZlbl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IkRvZSIsImRlZ3JlZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgaW4gQ29tcHV0ZXIgU2NpZW5jZSJ9LCJwcm9vZiI6eyJ0eXBlIjoiRWQyNTUxOVNpZ25hdHVyZTIwMTgiLCJjcmVhdGVkIjoiMjAyNS0wMS0wMVQxMDowMDowMFoiLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJodHRwczovL2V4YW1wbGUuY29tL2tleXMvMTIzIiwicHJvb2ZQdXJwb3NlIjoiYXNzZXJ0aW9uTWV0aG9kIiwiY2hhbGxlbmdlIjoicmFuZG9tLWNoYWxsZW5nZS12YWx1ZSIsImRvbWFpbiI6ImV4YW1wbGUuY29tIiwicHJvb2ZWYWx1ZSI6ImJhc2U2NHVybC1lbmNvZGVkLXByb29mLXZhbHVlIn19LHsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkRyaXZlckxpY2Vuc2UiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6IkFsaWNlIERvZSIsImxpY2Vuc2VfbnVtYmVyIjoiMTIzNDU2NzgifSwicHJvb2YiOnsidHlwZSI6IkVkMjU1MTlTaWduYXR1cmUyMDE4IiwiY3JlYXRlZCI6IjIwMjUtMDEtMDFUMTE6MDA6MDBaIiwidmVyaWZpY2F0aW9uTWV0aG9kIjoiaHR0cHM6Ly9kbXYuZXhhbXBsZS5jb20va2V5cy80NTYiLCJwcm9vZlB1cnBvc2UiOiJhc3NlcnRpb25NZXRob2QiLCJjaGFsbGVuZ2UiOiJhbm90aGVyLWNoYWxsZW5nZS12YWx1ZSIsImRvbWFpbiI6ImRtdi5leGFtcGxlLmNvbSIsInByb29mVmFsdWUiOiJiYXNlNjR1cmwtZW5jb2RlZC1wcm9vZi12YWx1ZSJ9fV19fQ.UntYvN8d2A4nOffSKx7qa5A76Kn7uaCjpt0k8gRAXID7epFoSHlFZHNO5qJ8E-6kD3xYuoKp5uOYQr7Qpak0ZQ`,
		//	},
		//	wantErr: false,
		//},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vp, err := NewVPToken(tt.fields.RawToken)
			if err != nil {
				t.Fatal(err)
			}
			//TODO: ta in en configuration till validate som styr vilka kontroller som ska göras för att kunna testa specifika delar enklare.
			if err := vp.Validate(tt.holderPublicKey); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			//TODO lägg till asserts
		})
	}
}

func build_vp_jws_token_with_ldp_vc_credentials(signingMethod jwt.SigningMethod, holderPublicKey interface{}, keyID string) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"iss": "did:example:issuer",
		"aud": "did:example:verifier",
		"iat": now.Unix(),
		"exp": now.Add(time.Minute * 5).Unix(),
		"vp": map[string]interface{}{
			"@context": []string{
				"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/v2",
			},
			"type": []string{"VerifiablePresentation"},
			//	"verifiableCredential": []string{
			//		"eyJhbGciOiJFUzI1NiIsImtpZCI6IjE2In0...", //TODO(mk): use this for jwt and replace with generated credential (vc+sd-jwt with and without disclosures (and holder sign?)). Also change format in presentation_submission to "jwt_vc"
			//	},
			"verifiableCredential": []interface{}{
				map[string]interface{}{
					"@context": []string{
						"https://www.w3.org/2018/credentials/v1",
						"https://w3id.org/security/v2",
					},
					"id":           "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
					"type":         []string{"VerifiableCredential", "UniversityDegreeCredential"},
					"issuer":       "did:example:issuer",
					"issuanceDate": "2020-03-10T04:24:12.164Z",
					"credentialSubject": map[string]interface{}{
						"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
						"degree": map[string]interface{}{
							"type": "BachelorDegree",
							"name": "Bachelor of Science and Arts",
						},
					},
					"proof": map[string]interface{}{
						"type":               "Ed25519Signature2018",
						"created":            "2023-01-29T08:00:00Z",
						"verificationMethod": "did:example:issuer#key-1",
						"jws":                "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..",
					},
				},
				map[string]interface{}{
					"@context": []string{
						"https://www.w3.org/2018/credentials/v1",
						"https://w3id.org/security/v2",
					},
					"id":           "urn:uuid:d2760df0-c454-4b44-8795-85dda4e126c7",
					"type":         []string{"VerifiableCredential", "DriverLicenseCredential"},
					"issuer":       "did:example:issuer2",
					"issuanceDate": "2022-01-01T00:00:00Z",
					"credentialSubject": map[string]interface{}{
						"id":         "did:example:ebfeb1f712ebc6f1c276e12ec21",
						"givenName":  "Jane",
						"familyName": "Doe",
						"birthDate":  "1995-05-10",
					},
					"proof": map[string]interface{}{
						"type":               "Ed25519Signature2018",
						"created":            "2023-01-29T09:00:00Z",
						"verificationMethod": "did:example:issuer2#key-1",
						"jws":                "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..",
					},
				},
			},
		},
		"presentation_submission": map[string]interface{}{
			"id":            "ae73773e-3e39-4032-a1c2-a6b69087e5b6",
			"definition_id": "vp_definition_1",
			"descriptor_map": []map[string]interface{}{
				{
					"id":     "degree_input",
					"path":   "$.vp.verifiableCredential[0]",
					"format": "ldp_vc",
				},
				{
					"id":     "license_input",
					"path":   "$.vp.verifiableCredential[1]",
					"format": "ldp_vc",
				},
			},
		},
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["kid"] = keyID
	token.Header["typ"] = "JWS"

	switch signingMethod.(type) {
	case *jwt.SigningMethodECDSA:
		return token.SignedString(holderPublicKey.(*ecdsa.PrivateKey))
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		return token.SignedString(holderPublicKey.(*rsa.PrivateKey))
	case *jwt.SigningMethodEd25519:
		return token.SignedString(holderPublicKey.(ed25519.PrivateKey))
	case *jwt.SigningMethodHMAC:
		return token.SignedString(holderPublicKey.([]byte))
	default:
		return "", fmt.Errorf("unknown signingmethod")
	}
}

func generateECDSAKeyPair(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func generateECDSAKeyPairSecp256k1() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func generateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func generateEdDSAKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

func generateHMACKey() ([]byte, error) {
	hmacKey := make([]byte, 32) // 256-bit HMAC-nyckel
	_, err := rand.Read(hmacKey)
	if err != nil {
		return nil, err
	}
	return hmacKey, nil
}

/* Below is a readable form for vp_token_1 in the test:
{
  "header": {
	"alg": "ES256",
	"typ": "JWT"
  },
  "payload": {
	"aud": "https://verifier.example.com",
	"iss": "https://wallet.example.com",
	"iat": 1738065899,
	"exp": 1738152299,
	"nonce": "randomly-generated-nonce",
	"vp": {
	  "@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/ns/credentials/examples/v1"
	  ],
	  "type": ["VerifiablePresentation"],
	  "verifiableCredential": [
		{
		  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
		  "credentialSubject": {
			"given_name": "Alice",
			"family_name": "Doe",
			"degree": "Bachelor of Science in Computer Science"
		  },
		  "proof": {
			"type": "Ed25519Signature2018",
			"created": "2025-01-01T10:00:00Z",
			"verificationMethod": "https://example.com/keys/123",
			"proofPurpose": "assertionMethod",
			"challenge": "random-challenge-value",
			"domain": "example.com",
			"proofValue": "base64url-encoded-proof-value"
		  }
		},
		{
		  "type": ["VerifiableCredential", "DriverLicense"],
		  "credentialSubject": {
			"name": "Alice Doe",
			"license_number": "12345678"
		  },
		  "proof": {
			"type": "Ed25519Signature2018",
			"created": "2025-01-01T11:00:00Z",
			"verificationMethod": "https://dmv.example.com/keys/456",
			"proofPurpose": "assertionMethod",
			"challenge": "another-challenge-value",
			"domain": "dmv.example.com",
			"proofValue": "base64url-encoded-proof-value"
		  }
		}
	  ]
	}
  }
}
*/
