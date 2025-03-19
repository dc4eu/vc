package education

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

func TestMicrocredentialMarshal(t *testing.T) {
	tts := []struct {
		name string
		have *MicrocredentialDocument
		want string
	}{
		{
			name: "success",
			have: &MicrocredentialDocument{
				IdentificationOfTheLearner: IdentificationOfTheLearner{
					Citizenship:        "test-citizenship",
					GivenNames:         "test-given-names",
					FamilyName:         "test-family-name",
					NationalId:         "test-national-id",
					DateOfBirth:        "test-date-of-birth",
					ContactInformation: "test-contact-information",
				},
				TitleOfTheMicroCredential: TitleOfTheMicroCredential{
					ISCEDCode: "test-isced-code",
					Title:     "test-title",
				},
				CountryOrRegionOfTheIssuer: CountryOrRegionOfTheIssuer{
					Country: "test-country",
				},
				AwardingBody: AwardingBody{
					TaxIdentifier: "test-tax-identifier",
					Title:         "test-title",
					LegalName:     "test-legal-name",
					URL:           "test-url",
				},
				DateOfIssuing: "test-date-of-issuing",
				LearningOutcomes: LearningOutcomes{
					MoreInformation:   "test-more-information",
					RelatedESCOSkills: "test-related-escoskills",
					RelatedSkills:     "test-related-skills",
					ReusabilityLevel:  "test-reusability-level",
					Title:             "test-title",
					Type:              "test-type",
				},
				EducationLevel: EducationLevel{
					EducationSubject: "test-education-subject",
					EducationLevel:   "test-education-level",
					EQFLevel:         "test-eqf-level",
					QFLevel:          "test-qf-level",
				},
				TypeOfAssessment: TypeOfAssessment{
					Type:        "test-type",
					Description: "test-description",
					Grade:       "test-grade",
				},
				FormOfParticipation: FormOfParticipation{
					Type: "test-type",
					Mode: "test-mode",
				},
				QualityAssurance: QualityAssurance{
					Identifier: "test-identifier",
					Title:      "test-title",
					Type:       "test-type",
				},
				NotionalWorkload:                   "test-notional-workload",
				Prerequisites:                      "test-prerequisites",
				SupervisionAndIdentityVerification: "test-supervision-and-identity-verification",
				GradeAchieved:                      "test-grade-achieved",
				IntegrationStackabilityOptions:     "test-integration-stackability-options",
				Link:                               "test-link",
			},
			want: "microcredential.golden",
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
