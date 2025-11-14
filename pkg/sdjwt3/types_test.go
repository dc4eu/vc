package sdjwt3

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiscloserHash(t *testing.T) {
	tts := []struct {
		name        string
		discloser   Discloser
		wantHash    string
		wantBase64  string
		wantContent []any
	}{
		{
			name: "Test Hashing Discloser",
			discloser: Discloser{
				Salt:      "6Ij7tM-a5iVPGboS5tmvVA",
				ClaimName: "email",
				Value:     "johndoe@example.com",
			},
			wantHash:    "kOavfTeY2HFVTfG6mhtzPNSfNVjZ77ItAjZvV9nnPFc",
			wantBase64:  "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0",
			wantContent: []any{"6Ij7tM-a5iVPGboS5tmvVA", "email", "johndoe@example.com"},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			gotHash, gotBase64, gotContent, err := tt.discloser.Hash()
			assert.NoError(t, err)

			assert.Equal(t, tt.wantHash, gotHash)
			assert.Equal(t, tt.wantBase64, gotBase64)
			assert.Equal(t, tt.wantContent, gotContent)
		})
	}
}

// ["6Ij7tM-a5iVPGboS5tmvVA", "email", "johndoe@example.com"]
