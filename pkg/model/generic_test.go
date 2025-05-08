package model

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeCredentialOffer(t *testing.T) {
	tts := []struct {
		name string
		have string
		want map[string]any
	}{
		{
			name: "working from greece wallet",
			have: "https://wallet.dc4eu.eu/cb?credential_offer=%7B%0A%20%20%22credential_issuer%22%3A%20%22https%3A%2F%2Fsatosa-test-1.sunet.se%22%2C%0A%20%20%22credential_configuration_ids%22%3A%20%5B%0A%20%20%20%20%22EHICCredential%22%0A%20%20%5D%2C%0A%20%20%22grants%22%3A%20%7B%0A%20%20%20%20%22authorization_code%22%3A%20%7B%0A%20%20%20%20%20%20%22issuer_state%22%3A%20%22authentic_source%3Dauthentic_source_se%26document_type%3DEHIC%26collect_id%3Dcollect_id_10%22%0A%20%20%20%20%7D%0A%20%20%7D%0A%7D",
			want: map[string]any{
				"credential_issuer": "https://satosa-test-1.sunet.se",
				"credential_configuration_ids": []string{
					"EHICCredential",
				},
				"grants": map[string]any{
					"authorization_code": map[string]any{
						"issuer_state": "authentic_source=authentic_source_se&document_type=EHIC&collect_id=collect_id_10",
					},
				},
			},
		},
		{
			name: "not working from credential constructorn",
			have: "https://wallet.dc4eu.eu/cb?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fsatosa-test-1.sunet.se%22%2C%22credential_configuration_ids%22%3A%5B%22EHICCredential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22collect_id%3Dcollect_id_ehic_86%5Cu0026document_type%3DEHIC%5Cu0026authentic_source%3DEHIC%3A00001%22%7D%7D%7D",
			want: map[string]any{
				"credential_issuer": "https://satosa-test-1.sunet.se",
				"credential_configuration_ids": []string{
					"EHICCredential",
				},
				"grants": map[string]any{
					"authorization_code": map[string]any{
						"issuer_state": "collect_id=collect_id_ehic_86\u0026document_type=EHIC\u0026authentic_source=EHIC:00001",
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			urlObject, err := url.Parse(tt.have)
			assert.NoError(t, err)

			values, err := url.ParseQuery(urlObject.RawQuery)
			assert.NoError(t, err)

			jsonWant, err := json.MarshalIndent(tt.want, "", "  ")
			assert.NoError(t, err)

			assert.JSONEq(t, string(jsonWant), values.Get("credential_offer"))

			fmt.Println("decoded", values.Get("credential_offer"))
		})
	}
}
