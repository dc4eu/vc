package openid4vci

import (
	"testing"
	"vc/pkg/jose"

	"github.com/stretchr/testify/assert"
)

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
				},
			},
			errStr: "",
		},
		{
			name: "ldp_vp",
			cr: &CredentialRequest{
				Proof: &Proof{
					ProofType: "ldp_vp",
				},
			},
			errStr: "",
		},
		{
			name: "attestation",
			cr: &CredentialRequest{
				Proof: &Proof{
					ProofType: "attestation",
				},
			},
			errStr: "",
		},
		{
			name: "mura",
			cr: &CredentialRequest{
				Proof: &Proof{
					ProofType: "mura",
				},
			},
			errStr: "invalid proof type",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := jose.ParseSigningKey("../../developer_tools/private_ec256.pem")
			assert.NoError(t, err)

			err = tt.cr.VerifyProof(privateKey.Public())
			if err != nil {
				assert.EqualError(t, err, tt.errStr)
			}
		})
	}
}

var mockJWT = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIiwidHlwIjoib3BlbmlkNHZjaS1wcm9vZitqd3QifQ.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tIiwiaWF0IjoxMzAwODE5MzgwLCJpc3MiOiJqb2UiLCJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJFUE5oQ0hnTGxkb01UYWtqNTFUampRMTZuc2ZCOGpqMW1VK2FRQjYwSmhRIiwieSI6ImR0cExndVh5WmV4RWdMYU5mRzhjdk81VzNmbGVEZFp2cm5LckE3YUZlVEEiLCJkIjoiSzBkbkFOMXNkQ1NFVEY3REgwMTRjT2RCZExLNFBrSlFRYzJQenBvcFBNRSJ9LCJub25jZSI6Im4tMFM2X1d6QTJNaiJ9.8g4m8qqsiQ9GdekfZ3tDAz7dJ8VMfYSjr71-2waTP_Z-IB_wNBX2BzHtoT-eiJ2GWZgxUCGwxSE_b80eIJIfkQ"

func TestVerifyProof(t *testing.T) {
	tts := []struct {
		name              string
		credentialRequest *CredentialRequest
		errStr            string
	}{
		{
			name: "valid jwt",
			credentialRequest: &CredentialRequest{
				CredentialIdentifier:      "ci_123",
				Proof: &Proof{
					ProofType: "jwt",
					JWT:       mockJWT,
				},
				CredentialResponseEncryption: &CredentialResponseEncryption{},
			},
			errStr: "",
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := jose.ParseSigningKey("../../developer_tools/private_ec256.pem")
			assert.NoError(t, err)

			if err := tt.credentialRequest.VerifyProof(privateKey.Public()); err != nil {
				assert.EqualError(t, err, tt.errStr)
			}
		})
	}
}
