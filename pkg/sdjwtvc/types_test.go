package sdjwtvc

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiscloserHash(t *testing.T) {
	tts := []struct {
		name        string
		discloser   *Discloser
		wantHash    string
		wantBase64  string
		wantContent []any
	}{
		{
			name: "Test Hashing Discloser",
			discloser: &Discloser{
				Salt:      "6Ij7tM-a5iVPGboS5tmvVA",
				ClaimName: "email",
				Value:     "johndoe@example.com",
			},
			wantHash:    "uAhW02Z-QRooOEI3WZp_2UURdgy1ZUxteC0mVxNLSHc",
			wantBase64:  "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0",
			wantContent: []any{"6Ij7tM-a5iVPGboS5tmvVA", "email", "johndoe@example.com"},
		},
		{
			name: "Test Hashing object",
			discloser: &Discloser{
				Salt:      "Qg_O64zqAxe412a108iroA",
				ClaimName: "address",
				Value: map[string]any{
					"street_address": "123 Main St",
					"locality":       "Anytown",
					"region":         "Anystate",
					"country":        "US",
				},
			},
			wantHash:    "fOmlYlHVsIDg5T5lCGIYgXoKBesC65snciS0dlDo_pU",
			wantBase64:  "WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwiYWRkcmVzcyIseyJjb3VudHJ5IjoiVVMiLCJsb2NhbGl0eSI6IkFueXRvd24iLCJyZWdpb24iOiJBbnlzdGF0ZSIsInN0cmVldF9hZGRyZXNzIjoiMTIzIE1haW4gU3QifV0",
			wantContent: []any{"Qg_O64zqAxe412a108iroA", "address", map[string]any{"street_address": "123 Main St", "locality": "Anytown", "region": "Anystate", "country": "US"}},
		},
		{
			name: "Test Hashing object",
			discloser: &Discloser{
				Salt:      "mockSalt",
				ClaimName: "personal_administrative_number",
				Value:     "40046784",
			},
			wantHash:    "GceftDe0ZXHZtP6ivadRpwPTNM0a7BCNyyDGFrS-2TE",
			wantBase64:  "WyJtb2NrU2FsdCIsInBlcnNvbmFsX2FkbWluaXN0cmF0aXZlX251bWJlciIsIjQwMDQ2Nzg0Il0",
			wantContent: []any{"mockSalt", "personal_administrative_number", "40046784"},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			gotHash, gotBase64, gotContent, err := tt.discloser.Hash(sha256.New())
			assert.NoError(t, err)

			assert.Equal(t, tt.wantHash, gotHash)
			assert.Equal(t, tt.wantBase64, gotBase64)
			assert.Equal(t, tt.wantContent, gotContent)
		})
	}
}
