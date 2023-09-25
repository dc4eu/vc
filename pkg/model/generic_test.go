package model

import (
	"encoding/json"
	"fmt"
	"testing"

	"vc/pkg/testv1"

	"github.com/stretchr/testify/assert"
)

func TestGenericUploadTestv1JSON(t *testing.T) {
	tts := []struct {
		name string
		have *GenericUpload
		want string
	}{
		{
			name: "testv1",
			have: &GenericUpload{
				Attributes: &GenericAttributes{
					DocumentType:            "testv1",
					DocumentID:              "1234567890",
					AuthenticSource:         "testv1",
					AuthenticSourcePersonID: "authentic_source_person_id",
					RevocationID:            "revocation_id",
					FirstName:               "first_name",
					LastName:                "last_name",
					DateOfBirth:             "date_of_birth",
					UID:                     "uid",
					LastNameAtBirth:         "last_name_at_birth",
					FirstNameAtBirth:        "first_name_at_birth",
					PlaceOfBirth:            "place_of_birth",
					CurrentAddress:          "current_address",
					Gender:                  "gender",
				},
				Document: &GenericDocument{
					Testv1: &testv1.Document{
						Name: testv1.Name{
							GivenName:  "given_name",
							FamilyName: "family_name",
						},
						Address: testv1.Address{
							Country: "country",
							Street:  "street",
						},
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.MarshalIndent(tt.have, "", "  ")
			assert.NoError(t, err)
			fmt.Println(string(got))
		})
	}
}
