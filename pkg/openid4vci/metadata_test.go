package openid4vci

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
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
