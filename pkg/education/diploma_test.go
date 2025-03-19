package education

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

func TestDiplomaMarshal(t *testing.T) {
	tts := []struct {
		name string
		have *DiplomaDocument
		want string
	}{
		{
			name: "success",
			have: &DiplomaDocument{
				DataOfBirth:        "test-date-of-birth",
				FamilyName:         "test-family-name",
				GivenName:          "test-given-name",
				PersonalIdentifier: "test-personal-identifier",
				NameOfAwardingTertiaryEducationInstitution:      "test-name-of-awarding-tertiary-education-institution",
				NameOfQualification:                             "test-name-of-qualification",
				DateOfAward:                                     "test-date-of-award",
				CountryOfAwardOfAcademicQualification:           "test-country-of-award-of-academic-qualification",
				OverallClassificationOfTheAcademicQualification: "test-overall-classification-of-the-academic-qualification",
				NameOfQualificationStudyField:                   "test-name-of-qualification-study-field",
				DegreeProjectTitle:                              "test-degree-project-title",
				Entitlement:                                     "test-entitlement",
				OtherInformation:                                "test-other-information",
			},
			want: "diploma.golden",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.have.Marshal()
			assert.NoError(t, err)

			want := golden.Get(t, tt.want)

			wantMap := map[string]any{}
			err = json.Unmarshal(want, &wantMap)
			assert.NoError(t, err)

			assert.Equal(t, wantMap, got)
		})
	}
}
