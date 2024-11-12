package model

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQRGenerator(t *testing.T) {
	tts := []struct {
		name string
		have MetaData
		want *QR
	}{
		{
			name: "OK",
			have: MetaData{
				AuthenticSource: "test_authentic_source",
				DocumentVersion: "",
				DocumentType:    "PDA1",
				DocumentID:      "document_id_1",
				RealData:        false,
				Collect: &Collect{
					ID:         "collect_id_1",
					ValidUntil: 0,
				},
				Revocation:                &Revocation{},
				CredentialValidFrom:       0,
				CredentialValidTo:         0,
				DocumentDataValidationRef: "",
			},
			want: &QR{
				Base64Image:        "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",
				CredentialOfferURL: "https://wallet.dc4eu.eu/cb?credential_offer=%7B%22credential_issuer%22%3A%22issuer.sunet.se%22%2C%22credential_configuration_ids%22%3A%5B%22PDA1Credential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22collect_id%3Dcollect_id_1%5Cu0026document_type%3DPDA1%5Cu0026authentic_source%3Dtest_authentic_source%22%7D%7D%7D",
			},
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			got, err := tt.have.QRGenerator(ctx, "issuer.sunet.se", 2, 256)
			assert.NoError(t, err)

			t.Run("Check CredentialOffer", func(t *testing.T) {
				assert.Equal(t, tt.want.CredentialOfferURL, got.CredentialOfferURL)
			})

			t.Run("Check Base64Image", func(t *testing.T) {
				assert.Equal(t, tt.want.Base64Image, got.Base64Image)
			})

			fmt.Println("base64 image", got.Base64Image)
		})
	}
}
