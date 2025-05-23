package socialsecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
)

func generateDocument(t *testing.T) map[string]any {
	document := EHICDocument{
		PersonalAdministrativeNumber: "123123123",
		IssuingAuthority: IssuingAuthority{
			ID:   "1231231",
			Name: "SUNET",
		},
		IssuingCountry: "SE",
		DateOfExpiry:   "2038-01-19",
		DateOfIssuance: "2021-01-19",
		DocumentNumber: "123123123",
	}

	b, err := json.Marshal(document)
	assert.NoError(t, err)

	fmt.Println("Document", string(b))

	docMap := map[string]any{}

	err = json.Unmarshal(b, &docMap)
	assert.NoError(t, err)

	return docMap
}

var mockEHICJSON = `{
	"personal_administrative_number": "123123123",
	"issuing_authority": {
		"id": "1231231",
		"name": "SUNET"
	},
	"issuing_country": "SE",
	"date_of_expiry": "2038-01-19",
	"date_of_issuance": "2021-01-19",
	"document_number": "123123123"
}`

func mockEHICMap(t *testing.T) map[string]any {
	docMap := map[string]any{}

	err := json.Unmarshal([]byte(mockPDA1JSON), &docMap)
	assert.NoError(t, err)

	return docMap
}

func TestEHICSchemaValidation(t *testing.T) {
	tts := []struct {
		name    string
		payload *model.CompleteDocument
		want    error
	}{
		{
			name: "from struct to map",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "https://demo-issuer.wwwallet.org/public/creds/ehic/european-health-insurance-card-schema-dc4eu-01.json",
				},
				DocumentData: generateDocument(t),
			},
			want: nil,
		},
		{
			name: "from string to map",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "https://demo-issuer.wwwallet.org/public/creds/ehic/european-health-insurance-card-schema-dc4eu-01.json",
				},
				DocumentData: mockEHICMap(t),
			},
			want: nil,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			got := helpers.ValidateDocumentData(ctx, tt.payload, logger.NewSimple("test"))

			assert.Equal(t, tt.want, got)

		})
	}
}
