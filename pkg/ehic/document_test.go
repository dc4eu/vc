package ehic

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
	document := Document{
		Subject: Subject{
			Forename:    "Magnus",
			FamilyName:  "Svensson",
			DateOfBirth: "1986-02-23",
			OtherElements: OtherElements{
				Sex:               "01",
				ForenameAtBirth:   "Magnus",
				FamilyNameAtBirth: "Svensson",
			},
		},
		SocialSecurityPin: "1234",
		PeriodEntitlement: PeriodEntitlement{
			StartingDate: "1970-01-01",
			EndingDate:   "2038-01-19",
		},
		DocumentID: "12354",
		CompetentInstitution: CompetentInstitution{
			InstitutionID:      "SE:1234",
			InstitutionName:    "Myndigheten",
			InstitutionCountry: "SE",
		},
	}

	b, err := json.Marshal(document)
	assert.NoError(t, err)

	fmt.Println("Document", string(b))

	docMap := map[string]any{}

	err = json.Unmarshal(b, &docMap)
	assert.NoError(t, err)

	return docMap
}

var mockPDA1JSON = `{
    "subject": {
        "forename": "Magnus",
        "family_name": "Svensson",
        "date_of_birth": "1986-02-23",
        "other_elements": {
            "sex": "01",
            "forename_at_birth": "Magnus",
            "family_name_at_birth": "Svensson"
        }
    },
    "social_security_pin": "1234",
    "period_entitlement": {
        "starting_date": "1970-01-01",
        "ending_date": "2038-01-19"
    },
    "document_id": "12354",
    "competent_institution": {
        "institution_id": "SE:1234",
        "institution_name": "Myndigheten",
        "institution_country": "SE"
    }
}`

func mockPDA1Map(t *testing.T) map[string]any {
	docMap := map[string]any{}

	err := json.Unmarshal([]byte(mockPDA1JSON), &docMap)
	assert.NoError(t, err)

	return docMap
}

func TestSchemaValidation(t *testing.T) {
	tts := []struct {
		name    string
		payload *model.CompleteDocument
		want    error
	}{
		{
			name: "from struct to map",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "file://../../standards/schema_ehic.json",
				},
				DocumentData: generateDocument(t),
			},
			want: nil,
		},
		{
			name: "from string to map",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "file://../../standards/schema_ehic.json",
				},
				DocumentData: mockPDA1Map(t),
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
