package openid4vci

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
	"gotest.tools/v3/golden"
)

func TestValidateMetadata(t *testing.T) {
	tts := []struct {
		name           string
		goldenFileName string
		want           error
	}{
		{
			name:           "test",
			goldenFileName: "metadata_response.golden",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			fileByte := golden.Get(t, tt.goldenFileName)

			metadata := &CredentialIssuerMetadataParameters{}
			err := json.Unmarshal(fileByte, metadata)
			assert.NoError(t, err)

			if got := CheckSimple(metadata); got != nil {
				t.Log(got)
				t.FailNow()
			}
		})
	}
}

func TestMarshalMetadata(t *testing.T) {
	tts := []struct {
		name           string
		goldenFileName string
		want           *CredentialIssuerMetadataParameters
	}{
		{
			name:           "test",
			goldenFileName: "metadata_response.golden",
			want: &CredentialIssuerMetadataParameters{
				CredentialIssuer:           "http://vc_dev_apigw:8080",
				AuthorizationServers:       []string{"http://vc_dev_apigw:8080"},
				BatchCredentialEndpoint:    "http://vc_dev_apigw:8080/batch_credential",
				DeferredCredentialEndpoint: "http://vc_dev_apigw:8080/deferred_credential",
				NotificationEndpoint:       "",
				CredentialResponseEncryption: &MetadataCredentialResponseEncryption{
					AlgValuesSupported: []string{"ECDH-ES"},
					EncValuesSupported: []string{"A128GCM"},
					EncryptionRequired: false,
				},
				CredentialIdentifiersSupported: false,
				SignedMetadata:                 "",
				Display: []MetadataDisplay{
					{
						Name:   "Example University",
						Locale: "en-US",
						Logo:   MetadataLogo{},
					},
					{
						Name:   "Example Université",
						Locale: "fr-FR",
						Logo:   MetadataLogo{},
					},
				},
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"UniversityDegreeCredential": {
						Format:                               "jwt_vc_json",
						Scope:                                "UniversityDegree",
						CryptographicBindingMethodsSupported: []string{"did:example"},
						CredentialSigningAlgValuesSupported:  []string{"ES256"},
						CredentialDefinition: CredentialDefinition{
							Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							CredentialSubject: map[string]CredentialSubject{
								"given_name": {
									Display: []CredentialMetadataDisplay{
										{
											Name:   "Given Name",
											Locale: "en-US",
										},
									},
								},
								"family_name": {
									Display: []CredentialMetadataDisplay{
										{
											Name:   "Surname",
											Locale: "en-US",
										},
									},
								},
								"degree": {},
								"gpa": {
									Display: []CredentialMetadataDisplay{
										{
											Name: "GPA",
										},
									},
								},
							},
						},
						ProofsTypesSupported: map[string]ProofsTypesSupported{
							"jwt": {
								ProofSigningAlgValuesSupported: []string{"ES256"},
							},
						},
						Display: []CredentialMetadataDisplay{
							{
								Name:   "University Credential",
								Locale: "en-US",
								Logo: MetadataLogo{
									URL:     "https://university.example.edu/public/logo.png",
									AltText: "a square logo of a university",
								},
								Description:     "",
								BackgroundColor: "#12107c",
								BackgroundImage: MetadataBackgroundImage{},
								TextColor:       "#FFFFFF",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			fileByte := golden.Get(t, tt.goldenFileName)

			got := &CredentialIssuerMetadataParameters{}
			err := json.Unmarshal(fileByte, got)
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMarshalYAML(t *testing.T) {
	tts := []struct {
		name           string
		goldenFileName string
		want           *CredentialIssuerMetadataParameters
	}{
		{
			name:           "ehic",
			goldenFileName: "metadata_issuing_ehic_yaml.golden",
			want: &CredentialIssuerMetadataParameters{
				CredentialIssuer:           "http://vc_dev_apigw:8080",
				CredentialEndpoint:         "http://vc_dev_apigw:8080/credential",
				AuthorizationServers:       []string{"http://vc_dev_apigw:8080"},
				BatchCredentialEndpoint:    "http://vc_dev_apigw:8080/batch_credential",
				DeferredCredentialEndpoint: "http://vc_dev_apigw:8080/deferred_credential",
				NotificationEndpoint:       "http://vc_dev_apigw:8080/notification",
				CredentialResponseEncryption: &MetadataCredentialResponseEncryption{
					AlgValuesSupported: []string{"ECDH-ES"},
					EncValuesSupported: []string{"A129GCM"},
					EncryptionRequired: false,
				},
				CredentialIdentifiersSupported: false,
				SignedMetadata:                 "",
				Display: []MetadataDisplay{
					{
						Name:   "European Health Insurance Card",
						Locale: "en-US",
						Logo:   MetadataLogo{},
					},
					{
						Name:   "Carte européenne d'assurance maladie",
						Locale: "fr-FR",
						Logo:   MetadataLogo{},
					},
				},
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"EHICCredential": {
						Format:                               "jwt_vc_json",
						Scope:                                "EHIC",
						CryptographicBindingMethodsSupported: []string{"did:example"},
						CredentialSigningAlgValuesSupported:  []string{"ES256"},
						CredentialDefinition: CredentialDefinition{
							Type: []string{"VerifiableCredential", "EHICCredential"},
							CredentialSubject: map[string]CredentialSubject{
								"social_security_pin": {
									Mandatory: true,
									ValueType: "string",
									Display: []CredentialMetadataDisplay{
										{
											Name:        "Social Security Number",
											Locale:      "en-US",
											Description: "The social security number of the EHIC holder",
										},
									},
								},
								"institution_country": {
									Mandatory: true,
									ValueType: "string",
									Display: []CredentialMetadataDisplay{
										{
											Name:        "Issuer Country",
											Locale:      "en-US",
											Description: "The issuer country of the EHIC holder",
										},
									},
								},
								"institution_id": {
									Mandatory: true,
									ValueType: "string",
									Display: []CredentialMetadataDisplay{
										{
											Name:        "Issuer Institution Code",
											Locale:      "en-US",
											Description: "The issuer institution code of the EHIC holder",
										},
									},
								},
								"document_id": {
									Mandatory: true,
									ValueType: "string",
									Display: []CredentialMetadataDisplay{
										{
											Name:        "Identification card number",
											Locale:      "en-US",
											Description: "The Identification card number of the EHIC holder",
										},
									},
								},
								"ending_date": {
									Mandatory: true,
									ValueType: "string",
									Display: []CredentialMetadataDisplay{
										{
											Name:        "Expiry Date",
											Locale:      "en-US",
											Description: "The date and time expired this credential",
										},
									},
								},
							},
						},
						Display: []CredentialMetadataDisplay{
							{
								Name:   "European Health Insurance Card Credential",
								Locale: "en-US",
								Logo: MetadataLogo{
									URL:     "https://example.edu/public/logo.png",
									AltText: "a square logo of a EHIC card",
								},
								Description:     "",
								BackgroundColor: "#12107c",
								BackgroundImage: MetadataBackgroundImage{
									URI: "https://example.edu/public/background.png",
								},
								TextColor: "#FFFFFF",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			fileByte := golden.Get(t, tt.goldenFileName)

			metadata := &CredentialIssuerMetadataParameters{}
			err := yaml.Unmarshal(fileByte, metadata)
			assert.NoError(t, err)

			assert.Equal(t, tt.want, metadata)
		})
	}
}
