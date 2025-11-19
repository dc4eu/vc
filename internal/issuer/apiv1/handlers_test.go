package apiv1

import (
	"context"
	"testing"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/logger"

	"github.com/stretchr/testify/assert"
)

var mockEhic = []byte(`
{
  "authentic_source": {
    "id": "CLEISS",
    "name": "SUNET"
  },
  "date_of_expiry": "2026-04-12",
  "date_of_issuance": "2023-11-18",
  "ending_date": "2026-06-24",
  "issuing_authority": {
    "id": "CLEISS",
    "name": "SUNET"
  },
  "issuing_country": "FR",
  "starting_date": "2025-06-24",
  "personal_administrative_number": "123456789A",
  "document_number": "EHIC1234567890"
}
  `)

func TestMakeSDJWT(t *testing.T) {
	tests := []struct {
		name    string
		request *CreateCredentialRequest
		wantErr bool
	}{
		{
			name: "Test EHIC SD-JWT Creation",
			request: &CreateCredentialRequest{
				DocumentType: "ehic", // Use config key, not URN
				DocumentData: mockEhic,
				JWK: &apiv1_issuer.Jwk{
					Kty: "EC",
					Crv: "P-256",
					X:   "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
					Y:   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			log := logger.NewSimple("test")
			client := mockNewClient(ctx, t, "ecdsa", log)

			got, err := client.MakeSDJWT(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, got)
			assert.NotEmpty(t, got.Data)
			assert.NotEmpty(t, got.Data[0].Credential)
		})
	}
}
