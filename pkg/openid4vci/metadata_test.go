package openid4vci

import (
	"crypto/ecdsa"
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
	"gotest.tools/v3/golden"
)

var mockIssuerMetadata = &CredentialIssuerMetadataParameters{
	CredentialIssuer:   "http://vc_dev_apigw:8080",
	CredentialEndpoint: "http://vc_dev_apigw:8080/credential",
	Display: []MetadataDisplay{
		{
			Name:   "SUNET wwWallet Issuer",
			Locale: "en-US",
		},
	},
	CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
		"urn:eudi:pid:1": {
			VCT:                                  "urn:eudi:pid:1",
			Format:                               "vc+sd-jwt",
			Scope:                                "pid:sd_jwt_vc",
			CryptographicBindingMethodsSupported: []string{"ES256"},
			CredentialSigningAlgValuesSupported:  []string{"ES256"},
			ProofTypesSupported: map[string]ProofsTypesSupported{
				"jwt": {
					ProofSigningAlgValuesSupported: []string{"ES256"},
				},
			},
			Display: []CredentialMetadataDisplay{
				{
					Name:            "PID SD-JWT VC",
					Locale:          "en-US",
					Description:     "Person Identification Data",
					BackgroundColor: "#1b263b",
					BackgroundImage: MetadataBackgroundImage{
						URI: "http://vc_dev_apigw:8080/images/background-image.png",
					},
					TextColor: "#FFFFFF",
				},
			},
		},
		"eu.europa.ec.eudi.pid.1": {
			Format:                               "mso_mdoc",
			Scope:                                "pid:mso_mdoc",
			Doctype:                              "eu.europa.ec.eudi.pid.1",
			CryptographicBindingMethodsSupported: []string{"ES256"},
			CredentialSigningAlgValuesSupported:  []string{"ES256"},
			ProofTypesSupported: map[string]ProofsTypesSupported{
				"jwt": {
					ProofSigningAlgValuesSupported: []string{"ES256"},
				},
			},
			Display: []CredentialMetadataDisplay{
				{
					Name:            "PID - MDOC",
					Locale:          "en-US",
					Description:     "Person Identification Data",
					BackgroundColor: "#4CC3DD",
					BackgroundImage: MetadataBackgroundImage{
						URI: "http://vc_dev_apigw:8080/images/background-image.png",
					},
					TextColor: "#000000",
				},
			},
		},
		"urn:credential:diploma": {
			VCT:                                  "urn:credential:diploma",
			Format:                               "vc+sd-jwt",
			Scope:                                "diploma",
			CryptographicBindingMethodsSupported: []string{"ES256"},
			CredentialSigningAlgValuesSupported:  []string{"ES256"},
			ProofTypesSupported: map[string]ProofsTypesSupported{
				"jwt": {
					ProofSigningAlgValuesSupported: []string{"ES256"},
				},
			},
			Display: []CredentialMetadataDisplay{
				{
					Name:   "Bachelor Diploma - SD-JWT VC",
					Locale: "en-US",
					Logo: MetadataLogo{
						URI: "http://vc_dev_apigw:8080/images/diploma-logo.png",
					},
					BackgroundColor: "#b1d3ff",
					BackgroundImage: MetadataBackgroundImage{
						URI: "http://vc_dev_apigw:8080/images/background-image.png",
					},
					TextColor: "#ffffff",
				},
			},
		},
		"urn:credential:ehic": {
			VCT:                                  "urn:credential:ehic",
			Format:                               "vc+sd-jwt",
			Scope:                                "ehic",
			CryptographicBindingMethodsSupported: []string{"ES256"},
			CredentialSigningAlgValuesSupported:  []string{"ES256"},
			ProofTypesSupported: map[string]ProofsTypesSupported{
				"jwt": {
					ProofSigningAlgValuesSupported: []string{"ES256"},
				},
			},
			Display: []CredentialMetadataDisplay{
				{
					Name:            "EHIC - SD-JWT VC",
					Locale:          "en-US",
					Description:     "European Health Insurance Card",
					BackgroundColor: "#1b263b",
					BackgroundImage: MetadataBackgroundImage{
						URI: "http://vc_dev_apigw:8080/images/background-image.png",
					},
					TextColor: "#FFFFFF",
				},
			},
		},
		"urn:eu.europa.ec.eudi:por:1": {
			VCT:                                  "urn:eu.europa.ec.eudi:por:1",
			Format:                               "vc+sd-jwt",
			Scope:                                "por:sd_jwt_vc",
			CryptographicBindingMethodsSupported: []string{"ES256"},
			CredentialSigningAlgValuesSupported:  []string{"ES256"},
			ProofTypesSupported: map[string]ProofsTypesSupported{
				"jwt": {
					ProofSigningAlgValuesSupported: []string{"ES256"},
				},
			},
			Display: []CredentialMetadataDisplay{
				{
					Name:            "POR - SD-JWT VC",
					Locale:          "en-US",
					Description:     "Power of Representation",
					BackgroundColor: "#c3b25d",
					BackgroundImage: MetadataBackgroundImage{
						URI: "http://vc_dev_apigw:8080/images/background-image.png",
					},
					TextColor: "#363531",
				},
			},
		},
	},
	SignedMetadata: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDTGpDQ0FkV2dBd0lCQWdJVWRnRVNiVEc5bnhTWFZJbUZkRkhIQUhHSjlSNHdDZ1lJS29aSXpqMEVBd0l3SURFUk1BOEdBMVVFQXd3SWQzZFhZV3hzWlhReEN6QUpCZ05WQkFZVEFrZFNNQjRYRFRJMU1ETXlNREE0TlRJME4xb1hEVE0xTURNeE9EQTROVEkwTjFvd01ERWhNQjhHQTFVRUF3d1laR1Z0YnkxcGMzTjFaWEl1ZDNkM1lXeHNaWFF1YjNKbk1Rc3dDUVlEVlFRR0V3SkhVakJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCT3NlU20xY1VSWnJpbkdNMGFFZHNMM21ERzlvbTBtUTFFSmR0bG1VQkl5RWxvcTZsdVlqNkdvQnA5VnpacDYwcGpZWSt5dEpiV2tiQURJVXNteXFibitqZ2R3d2dka3dId1lEVlIwakJCZ3dGb0FVZkhqNGJ6eXZvNHVuSHlzR3QrcE5hMFhzQmFJd0NRWURWUjBUQkFJd0FEQUxCZ05WSFE4RUJBTUNCYUF3RXdZRFZSMGxCQXd3Q2dZSUt3WUJCUVVIQXdFd2FnWURWUjBSQkdNd1lZSVlkMkZzYkdWMExXVnVkR1Z5Y0hKcGMyVXRhWE56ZFdWeWdoTnBjM04xWlhJdWQzZDNZV3hzWlhRdWIzSm5naGhrWlcxdkxXbHpjM1ZsY2k1M2QzZGhiR3hsZEM1dmNtZUNGbkZoTFdsemMzVmxjaTUzZDNkaGJHeGxkQzV2Y21jd0hRWURWUjBPQkJZRUZLYWZhODdEUWJyWFlZdUplN1lvQ29Kb0dLL0xNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJQjRXM1NiMG5LYm5iOFk3YUlaNG5qSkc3bEdTbTF4V09XUU1yQ3dneDlONUFpQmxJYTRFQVdmOU5pNFVNZVdGU1dJMktPQzVwUnlPQUVCU0dhdzlTK1BUd0E9PSJdfQ.eyJjcmVkZW50aWFsX2lzc3VlciI6Imh0dHBzOi8vaXNzdWVyLmRldi53YWxsZXQuc3VuZXQuc2UiLCJjcmVkZW50aWFsX2VuZHBvaW50IjoiaHR0cHM6Ly9pc3N1ZXIuZGV2LndhbGxldC5zdW5ldC5zZS9vcGVuaWQ0dmNpL2NyZWRlbnRpYWwiLCJkaXNwbGF5IjpbeyJuYW1lIjoiU1VORVQgd3dXYWxsZXQgSXNzdWVyIiwibG9jYWxlIjoiZW4tVVMifV0sImNyZWRlbnRpYWxfY29uZmlndXJhdGlvbnNfc3VwcG9ydGVkIjp7InVybjpldWRpOnBpZDoxIjp7InNjb3BlIjoicGlkOnNkX2p3dF92YyIsInZjdCI6InVybjpldWRpOnBpZDoxIiwiZGlzcGxheSI6W3sibmFtZSI6IlBJRCBTRC1KV1QgVkMiLCJkZXNjcmlwdGlvbiI6IlBlcnNvbiBJZGVudGlmaWNhdGlvbiBEYXRhIiwiYmFja2dyb3VuZF9pbWFnZSI6eyJ1cmkiOiJodHRwczovL2lzc3Vlci5kZXYud2FsbGV0LnN1bmV0LnNlL2ltYWdlcy9iYWNrZ3JvdW5kLWltYWdlLnBuZyJ9LCJiYWNrZ3JvdW5kX2NvbG9yIjoiIzFiMjYzYiIsInRleHRfY29sb3IiOiIjRkZGRkZGIiwibG9jYWxlIjoiZW4tVVMifV0sImZvcm1hdCI6InZjK3NkLWp3dCIsImNyeXB0b2dyYXBoaWNfYmluZGluZ19tZXRob2RzX3N1cHBvcnRlZCI6WyJFUzI1NiJdLCJjcmVkZW50aWFsX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiXSwicHJvb2ZfdHlwZXNfc3VwcG9ydGVkIjp7Imp3dCI6eyJwcm9vZl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2Il19fX0sImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIjp7InNjb3BlIjoicGlkOm1zb19tZG9jIiwiZG9jdHlwZSI6ImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwiZGlzcGxheSI6W3sibmFtZSI6IlBJRCAtIE1ET0MiLCJkZXNjcmlwdGlvbiI6IlBlcnNvbiBJZGVudGlmaWNhdGlvbiBEYXRhIiwiYmFja2dyb3VuZF9pbWFnZSI6eyJ1cmkiOiJodHRwczovL2lzc3Vlci5kZXYud2FsbGV0LnN1bmV0LnNlL2ltYWdlcy9iYWNrZ3JvdW5kLWltYWdlLnBuZyJ9LCJiYWNrZ3JvdW5kX2NvbG9yIjoiIzRDQzNERCIsInRleHRfY29sb3IiOiIjMDAwMDAwIiwibG9jYWxlIjoiZW4tVVMifV0sImZvcm1hdCI6Im1zb19tZG9jIiwiY3J5cHRvZ3JhcGhpY19iaW5kaW5nX21ldGhvZHNfc3VwcG9ydGVkIjpbIkVTMjU2Il0sImNyZWRlbnRpYWxfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJFUzI1NiJdLCJwcm9vZl90eXBlc19zdXBwb3J0ZWQiOnsiand0Ijp7InByb29mX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiXX19fSwidXJuOmNyZWRlbnRpYWw6ZGlwbG9tYSI6eyJzY29wZSI6ImRpcGxvbWEiLCJ2Y3QiOiJ1cm46Y3JlZGVudGlhbDpkaXBsb21hIiwiZm9ybWF0IjoidmMrc2Qtand0IiwiZGlzcGxheSI6W3sibmFtZSI6IkJhY2hlbG9yIERpcGxvbWEgLSBTRC1KV1QgVkMiLCJiYWNrZ3JvdW5kX2ltYWdlIjp7InVyaSI6Imh0dHBzOi8vaXNzdWVyLmRldi53YWxsZXQuc3VuZXQuc2UvaW1hZ2VzL2JhY2tncm91bmQtaW1hZ2UucG5nIn0sImxvZ28iOnsidXJpIjoiaHR0cHM6Ly9pc3N1ZXIuZGV2LndhbGxldC5zdW5ldC5zZS9pbWFnZXMvZGlwbG9tYS1sb2dvLnBuZyJ9LCJiYWNrZ3JvdW5kX2NvbG9yIjoiI2IxZDNmZiIsInRleHRfY29sb3IiOiIjZmZmZmZmIiwibG9jYWxlIjoiZW4tVVMifV0sImNyeXB0b2dyYXBoaWNfYmluZGluZ19tZXRob2RzX3N1cHBvcnRlZCI6WyJFUzI1NiJdLCJjcmVkZW50aWFsX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiXSwicHJvb2ZfdHlwZXNfc3VwcG9ydGVkIjp7Imp3dCI6eyJwcm9vZl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2Il19fX0sInVybjpjcmVkZW50aWFsOmVoaWMiOnsic2NvcGUiOiJlaGljIiwidmN0IjoidXJuOmNyZWRlbnRpYWw6ZWhpYyIsImZvcm1hdCI6InZjK3NkLWp3dCIsImRpc3BsYXkiOlt7Im5hbWUiOiJFSElDIC0gU0QtSldUIFZDIiwiZGVzY3JpcHRpb24iOiJFdXJvcGVhbiBIZWFsdGggSW5zdXJhbmNlIENhcmQiLCJiYWNrZ3JvdW5kX2ltYWdlIjp7InVyaSI6Imh0dHBzOi8vaXNzdWVyLmRldi53YWxsZXQuc3VuZXQuc2UvaW1hZ2VzL2JhY2tncm91bmQtaW1hZ2UucG5nIn0sImJhY2tncm91bmRfY29sb3IiOiIjMWIyNjNiIiwidGV4dF9jb2xvciI6IiNGRkZGRkYiLCJsb2NhbGUiOiJlbi1VUyJ9XSwiY3J5cHRvZ3JhcGhpY19iaW5kaW5nX21ldGhvZHNfc3VwcG9ydGVkIjpbIkVTMjU2Il0sImNyZWRlbnRpYWxfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJFUzI1NiJdLCJwcm9vZl90eXBlc19zdXBwb3J0ZWQiOnsiand0Ijp7InByb29mX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiXX19fSwidXJuOmV1LmV1cm9wYS5lYy5ldWRpOnBvcjoxIjp7InNjb3BlIjoicG9yOnNkX2p3dF92YyIsInZjdCI6InVybjpldS5ldXJvcGEuZWMuZXVkaTpwb3I6MSIsImRpc3BsYXkiOlt7Im5hbWUiOiJQT1IgLSBTRC1KV1QgVkMiLCJkZXNjcmlwdGlvbiI6IlBvd2VyIG9mIFJlcHJlc2VudGF0aW9uIiwiYmFja2dyb3VuZF9pbWFnZSI6eyJ1cmkiOiJodHRwczovL2lzc3Vlci5kZXYud2FsbGV0LnN1bmV0LnNlL2ltYWdlcy9iYWNrZ3JvdW5kLWltYWdlLnBuZyJ9LCJiYWNrZ3JvdW5kX2NvbG9yIjoiI2MzYjI1ZCIsInRleHRfY29sb3IiOiIjMzYzNTMxIiwibG9jYWxlIjoiZW4tVVMifV0sImZvcm1hdCI6InZjK3NkLWp3dCIsImNyeXB0b2dyYXBoaWNfYmluZGluZ19tZXRob2RzX3N1cHBvcnRlZCI6WyJFUzI1NiJdLCJjcmVkZW50aWFsX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiXSwicHJvb2ZfdHlwZXNfc3VwcG9ydGVkIjp7Imp3dCI6eyJwcm9vZl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2Il19fX19LCJtZG9jX2lhY2FzX3VyaSI6Imh0dHBzOi8vaXNzdWVyLmRldi53YWxsZXQuc3VuZXQuc2UvbWRvYy1pYWNhcyIsImlhdCI6MTc0NzA1NTQxNCwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZGV2LndhbGxldC5zdW5ldC5zZSIsInN1YiI6Imh0dHBzOi8vaXNzdWVyLmRldi53YWxsZXQuc3VuZXQuc2UifQ.lScrOAAR4J6GEc3oSK8AUYLRETWKZksQnJT-Dk4Pf82ZsYdnKxARRCJmgCPjr0-UvJFEsWDWbAxRWtBN74oSaA",
}

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
			goldenFileName: "issuer_metadata_json.golden",
			want:           mockIssuerMetadata,
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

func TestSignIssuerMetadata(t *testing.T) {
	tts := []struct {
		name           string
		issuerMetadata *CredentialIssuerMetadataParameters
	}{
		{
			name:           "test",
			issuerMetadata: mockIssuerMetadata,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			metadata := tt.issuerMetadata

			signingKey, cert := mockGenerateECDSAKey(t)
			pubKey := signingKey.Public()

			metadataWithSignature, err := metadata.Sign(jwt.SigningMethodES256, signingKey, []string{cert})
			assert.NoError(t, err)

			assert.NotEmpty(t, metadataWithSignature)

			claims := jwt.MapClaims{}

			token, err := jwt.ParseWithClaims(metadataWithSignature.SignedMetadata, claims, func(token *jwt.Token) (any, error) {
				return pubKey.(*ecdsa.PublicKey), nil
			})
			assert.NoError(t, err)

			assert.True(t, token.Valid)

			// ensure the singed claim does not have signed_metadata in it self
			assert.Empty(t, claims["signed_metadata"])

			assert.Len(t, token.Header["x5c"], 1)
		})
	}
}

func TestMarshal(t *testing.T) {
	want := &CredentialIssuerMetadataParameters{
		CredentialIssuer:           "http://vc_dev_apigw:8080",
		CredentialEndpoint:         "http://vc_dev_apigw:8080/credential",
		AuthorizationServers:       []string{"http://vc_dev_apigw:8080"},
		DeferredCredentialEndpoint: "http://vc_dev_apigw:8080/deferred_credential",
		NotificationEndpoint:       "http://vc_dev_apigw:8080/notification",
		CredentialResponseEncryption: &MetadataCredentialResponseEncryption{
			AlgValuesSupported: []string{"ECDH-ES"},
			EncValuesSupported: []string{"A128GCM"},
			EncryptionRequired: false,
		},
		SignedMetadata: "",
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
				VCT:                                  "EHICCredential",
				Format:                               "vc+sd-jwt",
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
							URI:     "https://example.edu/public/logo.png",
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
	}

	t.Run("yaml", func(t *testing.T) {
		fileByte := golden.Get(t, "metadata_issuing_ehic_yaml.golden")

		metadata := &CredentialIssuerMetadataParameters{}
		err := yaml.Unmarshal(fileByte, metadata)
		assert.NoError(t, err)

		assert.Equal(t, want, metadata)
	})

	t.Run("json", func(t *testing.T) {
		fileByte := golden.Get(t, "metadata_issuing_ehic_json.golden")

		metadata := &CredentialIssuerMetadataParameters{}
		err := json.Unmarshal(fileByte, metadata)
		assert.NoError(t, err)

		assert.Equal(t, want, metadata)
	})

}
