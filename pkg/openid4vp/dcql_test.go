package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

var mockDCQLExample = []byte(`{
  "credentials": [
    {
      "id": "my_credential",
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": [ "https://credentials.example.com/identity_credential" ]
      },
      "claims": [
          {"path": ["last_name"]},
          {"path": ["first_name"]},
          {"path": ["address", "street_address"]}
      ]
    }
  ]
}`)

var mockDCQLExampleFromWWWallet = []byte(`{
  "credentials": [
    {
      "id": "CustomVerifiableId0",
      "format": "vc+sd-jwt",
      "meta": {
        "vct_values": [
          "urn:eudi:pid:1"
        ]
      },
      "claims": [
        {
          "path": [
            "given_name"
          ]
        },
        {
          "path": [
            "birth_given_name"
          ]
        },
        {
          "path": [
            "family_name"
          ]
        },
        {
          "path": [
            "birth_family_name"
          ]
        },
        {
          "path": [
            "birthdate"
          ]
        },
        {
          "path": [
            "place_of_birth",
            "country"
          ]
        },
        {
          "path": [
            "place_of_birth",
            "region"
          ]
        },
        {
          "path": [
            "place_of_birth",
            "locality"
          ]
        },
        {
          "path": [
            "nationalities"
          ]
        },
        {
          "path": [
            "personal_administrative_number"
          ]
        },
        {
          "path": [
            "sex"
          ]
        },
        {
          "path": [
            "address",
            "formatted"
          ]
        },
        {
          "path": [
            "address",
            "street_address"
          ]
        },
        {
          "path": [
            "address",
            "house_number"
          ]
        },
        {
          "path": [
            "address",
            "postal_code"
          ]
        },
        {
          "path": [
            "address",
            "locality"
          ]
        },
        {
          "path": [
            "address",
            "region"
          ]
        },
        {
          "path": [
            "address",
            "country"
          ]
        },
        {
          "path": [
            "age_equal_or_over",
            "14"
          ]
        },
        {
          "path": [
            "age_equal_or_over",
            "16"
          ]
        },
        {
          "path": [
            "age_equal_or_over",
            "18"
          ]
        },
        {
          "path": [
            "age_equal_or_over",
            "21"
          ]
        },
        {
          "path": [
            "age_equal_or_over",
            "65"
          ]
        },
        {
          "path": [
            "age_in_years"
          ]
        },
        {
          "path": [
            "age_birth_year"
          ]
        },
        {
          "path": [
            "email"
          ]
        },
        {
          "path": [
            "phone_number"
          ]
        },
        {
          "path": [
            "issuing_authority"
          ]
        },
        {
          "path": [
            "issuing_country"
          ]
        },
        {
          "path": [
            "issuing_jurisdiction"
          ]
        },
        {
          "path": [
            "date_of_expiry"
          ]
        },
        {
          "path": [
            "date_of_issuance"
          ]
        },
        {
          "path": [
            "document_number"
          ]
        },
        {
          "path": [
            "picture"
          ]
        }
      ]
    }
  ],
  "credential_sets": [
    {
      "options": [
        [
          "CustomVerifiableId0"
        ]
      ],
      "purpose": "Purpose not specified"
    }
  ]
}`)

func TestExample(t *testing.T) {
	tts := []struct {
		name string
		have *DCQL
		want []byte
	}{
		{
			name: "example from spec",
			have: &DCQL{
				Credentials: []CredentialQuery{
					{
						ID:     "my_credential",
						Format: "dc+sd-jwt",
						Meta: MetaQuery{
							VCTValues: []string{"https://credentials.example.com/identity_credential"},
						},
						Claims: []ClaimQuery{
							{
								Path: []string{"last_name"},
							},
							{
								Path: []string{"first_name"},
							},
							{
								Path: []string{"address", "street_address"},
							},
						},
					},
				},
			},
			want: mockDCQLExample,
		},
		{
			name: "example from wwwallet",
			have: &DCQL{
				CredentialSets: []CredentialSetQuery{
					{
						Options: [][]string{
							{"CustomVerifiableId0"},
						},
						Purpose: "Purpose not specified",
					},
				},
				Credentials: []CredentialQuery{
					{
						ID:     "CustomVerifiableId0",
						Format: "vc+sd-jwt",
						Meta: MetaQuery{
							VCTValues: []string{"urn:eudi:pid:1"},
						},
						Claims: []ClaimQuery{
							{
								Path: []string{"given_name"},
							},
							{
								Path: []string{"birth_given_name"},
							},
							{
								Path: []string{"family_name"},
							},
							{
								Path: []string{"birth_family_name"},
							},
							{
								Path: []string{"birthdate"},
							},
							{
								Path: []string{"place_of_birth", "country"},
							},
							{
								Path: []string{"place_of_birth", "region"},
							},
							{
								Path: []string{"place_of_birth", "locality"},
							},
							{
								Path: []string{"nationalities"},
							},
							{
								Path: []string{"personal_administrative_number"},
							},
							{
								Path: []string{"sex"},
							},
							{
								Path: []string{"address", "formatted"},
							},
							{
								Path: []string{"address", "street_address"},
							},
							{
								Path: []string{"address", "house_number"},
							},
							{
								Path: []string{"address", "postal_code"},
							},
							{
								Path: []string{"address", "locality"},
							},
							{
								Path: []string{"address", "region"},
							},
							{
								Path: []string{"address", "country"},
							},
							{
								Path: []string{"age_equal_or_over", "14"},
							},
							{
								Path: []string{"age_equal_or_over", "16"},
							},
							{
								Path: []string{"age_equal_or_over", "18"},
							},
							{
								Path: []string{"age_equal_or_over", "21"},
							},
							{
								Path: []string{"age_equal_or_over", "65"},
							},
							{
								Path: []string{"age_in_years"},
							},
							{
								Path: []string{"age_birth_year"},
							},
							{
								Path: []string{"email"},
							},
							{
								Path: []string{"phone_number"},
							},
							{
								Path: []string{"issuing_authority"},
							},
							{
								Path: []string{"issuing_country"},
							},
							{
								Path: []string{"issuing_jurisdiction"},
							},
							{
								Path: []string{"date_of_expiry"},
							},
							{
								Path: []string{"date_of_issuance"},
							},
							{
								Path: []string{"document_number"},
							},
							{
								Path: []string{"picture"},
							},
						},
					},
				},
			},
			want: mockDCQLExampleFromWWWallet,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.MarshalIndent(tt.have, "", "  ")
			assert.NoError(t, err)

			assert.JSONEq(t, string(tt.want), string(got))

		})
	}
}
