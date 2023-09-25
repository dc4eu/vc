package ehic

import (
	"encoding/json"
	"fmt"
	"testing"
	"vc/pkg/eidas"

	"github.com/stretchr/testify/assert"
)

func TestDocument(t *testing.T) {
	tts := []struct {
		name     string
		document *Document
	}{
		{
			name: "test1",
			document: &Document{
				PID: eidas.Identification{
					FirstName:   "John",
					LastName:    "Doe",
					Gender:      "male",
					PINS:        []string{"1234567890"},
					ExhibitorID: "1234567890",
				},
				CardHolder: CardHolder{
					FamilyName:       "Smith",
					GivenName:        "Adam",
					BirthDate:        "1990-01-01",
					ID:               "1234567890",
					CardholderStatus: "active",
				},
				CompetentInstitution: CompetentInstitution{
					InstitutionName: "NHS",
					ID:              "1234567890",
				},
				CardInformation: CardInformation{
					ID:           "1234567890",
					IssuanceDate: "2019-01-01",
					ValidSince:   "2019-01-01",
					ExpiryDate:   "2020-01-01",
					InvalidSince: "2020-01-01",
					Signature: Signature{
						Issuer: "NHS",
						Seal:   "6f356f14d32aae22d1d7c782332d6a3cdc0860e7af73eff644c1773c419b323e",
					},
				},
				Signature: Signature{
					Issuer: "NHS",
					Seal:   "5ff28c8953c7b4c5acd71f476d75e800a7d032f40d935074e7d273c328906b70",
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.MarshalIndent(tt.document, "", "  ")
			assert.NoError(t, err)

			fmt.Println(string(got))
		})
	}
}
