package openid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestEC256Key generates an EC P-256 key pair for testing
func generateTestEC256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC256 key: %v", err)
	}
	return privateKey
}

// createValidJWTProof creates a valid JWT proof for testing
func createValidJWTProof(t *testing.T, privateKey *ecdsa.PrivateKey, aud string) string {
	t.Helper()

	// Create claims
	claims := jwtv5.MapClaims{
		"aud":   aud,
		"iat":   time.Now().Unix(),
		"nonce": "test-nonce",
	}

	// Create token with proper headers
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, claims)
	token.Header["typ"] = "openid4vci-proof+jwt"
	token.Header["jwk"] = map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test-x",
		"y":   "test-y",
	}

	// Sign the token
	signedToken, err := token.SignedString(privateKey)
	require.NoError(t, err)

	return signedToken
}

func TestProofTypes(t *testing.T) {
	tts := []struct {
		name   string
		cr     *CredentialRequest
		errStr string
	}{
		{
			name: "jwt",
			cr: &CredentialRequest{
				Proof: &Proof{
					ProofType: "jwt",
					JWT:       mockJWTWithKidAndJwk,
				},
			},
			errStr: "invalid_credential_request",
		},
		{
			name: "jwt_missing",
			cr: &CredentialRequest{
				Proof: &Proof{
					ProofType: "jwt",
				},
			},
			errStr: "invalid_credential_request",
		},
		{
			name: "di_vp",
			cr: &CredentialRequest{
				Proof: &Proof{
					ProofType: "di_vp",
					DIVP: map[string]interface{}{
						"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
						"type":     []interface{}{"VerifiablePresentation"},
						"proof": map[string]interface{}{
							"type":               "DataIntegrityProof",
							"cryptosuite":        "eddsa-2022",
							"proofPurpose":       "authentication",
							"verificationMethod": "did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro",
							"domain":             "https://example.com",
						},
					},
				},
			},
			errStr: "",
		},
		{
			name: "di_vp_missing",
			cr: &CredentialRequest{
				Proof: &Proof{
					ProofType: "di_vp",
				},
			},
			errStr: "invalid_credential_request",
		},
		{
			name: "attestation",
			cr: &CredentialRequest{
				Proof: &Proof{
					ProofType:   "attestation",
					Attestation: mockKeyAttestation,
				},
			},
			errStr: "",
		},
		{
			name: "attestation_missing",
			cr: &CredentialRequest{
				Proof: &Proof{
					ProofType: "attestation",
				},
			},
			errStr: "invalid_credential_request",
		},
		{
			name: "invalid_proof_type",
			cr: &CredentialRequest{
				Proof: &Proof{
					ProofType: "mura",
				},
			},
			errStr: "invalid_credential_request",
		},
		{
			name: "nil_proof",
			cr: &CredentialRequest{
				Proof: nil,
			},
			errStr: "invalid_credential_request",
		},
		{
			name: "empty_proof_type",
			cr: &CredentialRequest{
				Proof: &Proof{
					ProofType: "",
				},
			},
			errStr: "invalid_credential_request",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			privateKey := generateTestEC256Key(t)

			err := tt.cr.VerifyProof(privateKey.Public())
			if tt.errStr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errStr)
			}
		})
	}
}

// Mock JWT with both kid and jwk (invalid per spec)
var mockJWTWithKidAndJwk = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIiwidHlwIjoib3BlbmlkNHZjaS1wcm9vZitqd3QiLCJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJ0ZXN0IiwieSI6InRlc3QifX0.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tIiwiaWF0IjoxMzAwODE5MzgwfQ.invalid"

// Mock key attestation JWT
var mockKeyAttestation = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtleS1hdHRlc3RhdGlvbitqd3QifQ.eyJpYXQiOjEzMDA4MTkzODAsImF0dGVzdGVkX2tleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoidGVzdCIsInkiOiJ0ZXN0In1dfQ.invalid"

func TestVerifyProof(t *testing.T) {
	tts := []struct {
		name              string
		credentialRequest *CredentialRequest
		errStr            string
	}{
		{
			name: "valid jwt",
			credentialRequest: &CredentialRequest{
				CredentialIdentifier: "ci_123",
				Proof: &Proof{
					ProofType: "jwt",
					JWT:       mockJWTWithKidAndJwk,
				},
				CredentialResponseEncryption: &CredentialResponseEncryption{},
			},
			errStr: "invalid_credential_request",
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			privateKey := generateTestEC256Key(t)

			if err := tt.credentialRequest.VerifyProof(privateKey.Public()); err != nil {
				assert.Contains(t, err.Error(), tt.errStr)
			}
		})
	}
}

func TestVerifyJWTProof(t *testing.T) {
	privateKey := generateTestEC256Key(t)

	t.Run("valid JWT proof", func(t *testing.T) {
		jwt := createValidJWTProof(t, privateKey, "https://issuer.example.com")
		opts := &VerifyProofOptions{
			Audience: "https://issuer.example.com",
			CNonce:   "test-nonce",
		}
		err := verifyJWTProof(jwt, &privateKey.PublicKey, opts)
		assert.NoError(t, err)
	})

	t.Run("alg none rejected", func(t *testing.T) {
		// Create a token with alg=none
		claims := jwtv5.MapClaims{"aud": "test", "iat": time.Now().Unix()}
		token := jwtv5.NewWithClaims(jwtv5.SigningMethodNone, claims)
		token.Header["typ"] = "openid4vci-proof+jwt"
		token.Header["jwk"] = map[string]interface{}{"kty": "EC"}
		jwt, _ := token.SignedString(jwtv5.UnsafeAllowNoneSignatureType)

		err := verifyJWTProof(jwt, &privateKey.PublicKey, nil)
		assert.Error(t, err)
		// The error type should indicate invalid credential request
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})

	t.Run("missing typ rejected", func(t *testing.T) {
		claims := jwtv5.MapClaims{"aud": "test", "iat": time.Now().Unix()}
		token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, claims)
		// Not setting typ header
		token.Header["jwk"] = map[string]interface{}{"kty": "EC"}
		jwt, _ := token.SignedString(privateKey)

		err := verifyJWTProof(jwt, &privateKey.PublicKey, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})

	t.Run("wrong typ rejected", func(t *testing.T) {
		claims := jwtv5.MapClaims{"aud": "test", "iat": time.Now().Unix()}
		token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, claims)
		token.Header["typ"] = "wrong-type"
		token.Header["jwk"] = map[string]interface{}{"kty": "EC"}
		jwt, _ := token.SignedString(privateKey)

		err := verifyJWTProof(jwt, &privateKey.PublicKey, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})

	t.Run("private key in jwk rejected", func(t *testing.T) {
		claims := jwtv5.MapClaims{"aud": "test", "iat": time.Now().Unix()}
		token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, claims)
		token.Header["typ"] = "openid4vci-proof+jwt"
		token.Header["jwk"] = map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   "test",
			"y":   "test",
			"d":   "private-key-material", // This should be rejected
		}
		jwt, _ := token.SignedString(privateKey)

		err := verifyJWTProof(jwt, &privateKey.PublicKey, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})

	t.Run("nonce validation", func(t *testing.T) {
		claims := jwtv5.MapClaims{
			"aud":   "https://issuer.example.com",
			"iat":   time.Now().Unix(),
			"nonce": "correct-nonce",
		}
		token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, claims)
		token.Header["typ"] = "openid4vci-proof+jwt"
		token.Header["jwk"] = map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "test", "y": "test"}
		jwt, _ := token.SignedString(privateKey)

		// Test with matching nonce
		opts := &VerifyProofOptions{CNonce: "correct-nonce"}
		err := verifyJWTProof(jwt, &privateKey.PublicKey, opts)
		assert.NoError(t, err)

		// Test with wrong nonce
		opts = &VerifyProofOptions{CNonce: "wrong-nonce"}
		err = verifyJWTProof(jwt, &privateKey.PublicKey, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_nonce")
	})
}

func TestVerifyDIVPProof(t *testing.T) {
	t.Run("valid di_vp proof", func(t *testing.T) {
		divp := map[string]interface{}{
			"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
			"type":     []interface{}{"VerifiablePresentation"},
			"proof": map[string]interface{}{
				"type":               "DataIntegrityProof",
				"cryptosuite":        "eddsa-2022",
				"proofPurpose":       "authentication",
				"verificationMethod": "did:key:test",
				"domain":             "https://issuer.example.com",
				"challenge":          "test-nonce",
			},
		}
		opts := &VerifyProofOptions{
			Audience: "https://issuer.example.com",
			CNonce:   "test-nonce",
		}
		err := verifyDIVPProof(divp, opts)
		assert.NoError(t, err)
	})

	t.Run("missing @context rejected", func(t *testing.T) {
		divp := map[string]interface{}{
			"type": []interface{}{"VerifiablePresentation"},
		}
		err := verifyDIVPProof(divp, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})

	t.Run("missing VerifiablePresentation type rejected", func(t *testing.T) {
		divp := map[string]interface{}{
			"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
			"type":     []interface{}{"SomeOtherType"},
		}
		err := verifyDIVPProof(divp, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})

	t.Run("wrong proofPurpose rejected", func(t *testing.T) {
		divp := map[string]interface{}{
			"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
			"type":     []interface{}{"VerifiablePresentation"},
			"proof": map[string]interface{}{
				"proofPurpose":       "assertionMethod", // Should be "authentication"
				"domain":             "https://issuer.example.com",
				"cryptosuite":        "eddsa-2022",
				"verificationMethod": "did:key:test",
			},
		}
		err := verifyDIVPProof(divp, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})
}

func TestVerifyAttestationProof(t *testing.T) {
	t.Run("valid attestation", func(t *testing.T) {
		// This mock attestation has all required claims
		err := verifyAttestationProof(mockKeyAttestation, nil)
		assert.NoError(t, err)
	})

	t.Run("invalid attestation format", func(t *testing.T) {
		err := verifyAttestationProof("not-a-jwt", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})
}

func TestVerifyProofWithOptions(t *testing.T) {
	privateKey := generateTestEC256Key(t)

	t.Run("with audience validation", func(t *testing.T) {
		jwt := createValidJWTProof(t, privateKey, "https://correct-issuer.com")
		cr := &CredentialRequest{
			Proof: &Proof{
				ProofType: "jwt",
				JWT:       jwt,
			},
		}
		opts := &VerifyProofOptions{
			Audience: "https://correct-issuer.com",
			CNonce:   "test-nonce",
		}
		err := cr.VerifyProofWithOptions(&privateKey.PublicKey, opts)
		assert.NoError(t, err)
	})

	t.Run("audience mismatch", func(t *testing.T) {
		jwt := createValidJWTProof(t, privateKey, "https://wrong-issuer.com")
		cr := &CredentialRequest{
			Proof: &Proof{
				ProofType: "jwt",
				JWT:       jwt,
			},
		}
		opts := &VerifyProofOptions{
			Audience: "https://correct-issuer.com",
			CNonce:   "test-nonce",
		}
		err := cr.VerifyProofWithOptions(&privateKey.PublicKey, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})
}

func TestVerifyProofErrorDescriptions(t *testing.T) {
	privateKey := generateTestEC256Key(t)

	t.Run("nil proof returns proper error description", func(t *testing.T) {
		cr := &CredentialRequest{Proof: nil}
		err := cr.VerifyProof(privateKey.Public())
		assert.Error(t, err)
		openidErr, ok := err.(*Error)
		assert.True(t, ok)
		assert.Equal(t, ErrInvalidCredentialRequest, openidErr.Err)
		assert.Equal(t, "proof is required", openidErr.ErrorDescription)
	})

	t.Run("empty proof_type returns proper error description", func(t *testing.T) {
		cr := &CredentialRequest{Proof: &Proof{ProofType: ""}}
		err := cr.VerifyProof(privateKey.Public())
		assert.Error(t, err)
		openidErr, ok := err.(*Error)
		assert.True(t, ok)
		assert.Equal(t, ErrInvalidCredentialRequest, openidErr.Err)
		assert.Equal(t, "proof_type is required", openidErr.ErrorDescription)
	})

	t.Run("missing jwt field returns proper error description", func(t *testing.T) {
		cr := &CredentialRequest{Proof: &Proof{ProofType: "jwt"}}
		err := cr.VerifyProof(privateKey.Public())
		assert.Error(t, err)
		openidErr, ok := err.(*Error)
		assert.True(t, ok)
		assert.Equal(t, ErrInvalidCredentialRequest, openidErr.Err)
		assert.Equal(t, "jwt field is required for proof_type 'jwt'", openidErr.ErrorDescription)
	})

	t.Run("missing di_vp field returns proper error description", func(t *testing.T) {
		cr := &CredentialRequest{Proof: &Proof{ProofType: "di_vp"}}
		err := cr.VerifyProof(privateKey.Public())
		assert.Error(t, err)
		openidErr, ok := err.(*Error)
		assert.True(t, ok)
		assert.Equal(t, ErrInvalidCredentialRequest, openidErr.Err)
		assert.Equal(t, "di_vp field is required for proof_type 'di_vp'", openidErr.ErrorDescription)
	})

	t.Run("missing attestation field returns proper error description", func(t *testing.T) {
		cr := &CredentialRequest{Proof: &Proof{ProofType: "attestation"}}
		err := cr.VerifyProof(privateKey.Public())
		assert.Error(t, err)
		openidErr, ok := err.(*Error)
		assert.True(t, ok)
		assert.Equal(t, ErrInvalidCredentialRequest, openidErr.Err)
		assert.Equal(t, "attestation field is required for proof_type 'attestation'", openidErr.ErrorDescription)
	})

	t.Run("unsupported proof_type returns proper error description", func(t *testing.T) {
		cr := &CredentialRequest{Proof: &Proof{ProofType: "unknown"}}
		err := cr.VerifyProof(privateKey.Public())
		assert.Error(t, err)
		openidErr, ok := err.(*Error)
		assert.True(t, ok)
		assert.Equal(t, ErrInvalidCredentialRequest, openidErr.Err)
		assert.Equal(t, "unsupported proof_type: unknown", openidErr.ErrorDescription)
	})
}
