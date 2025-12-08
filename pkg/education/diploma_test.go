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
				Type: []string{"VerifiableCredential", "EuropeanDigitalCredential"},
				CredentialProfiles: Fat{
					ID:   "test-credential-profiles-id",
					Type: "test-credential-profiles-type",
					InScheme: DiplomaInScheme{
						ID:   "test-in-scheme-id",
						Type: "test-in-scheme-type",
					},
					PrefLabel: DiplomaPrefLabel{
						En: "test-pref-label-en",
					},
					Notation: "test-notation",
				},
				CredentialSchema: Fat{
					ID:   "test-credential-schema-id",
					Type: "test-credential-schema-type",
				},
				CredentialSubject: CredentialSubject{
					ID:          "test-credential-subject-id",
					Type:        "test-credential-subject-type",
					DateOfBirth: "test-date-of-birth",
					HasClaim: HasClaim{
						ID:   "test-has-claim-id",
						Type: "test-has-claim-type",
						AwardedBy: AwardedBy{
							ID:           "test-awarded-by-id",
							Type:         "test-awarded-by-type",
							AwardingDate: "test-awarding-date",
							AwardingBody: DiplomaAwardingBody{
								ID:   "test-awarding-body-id",
								Type: "test-awarding-body-type",
							},
						},
						Grade: DiplomaGrade{
							ID:          "test-grade-id",
							Type:        "test-grade-type",
							NoteLiteral: "test-note-literal",
						},
					},
				},
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
