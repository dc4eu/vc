package openid4vci

import (
	"crypto/ecdsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestCredentialIssuerMetadataParameters_UnmarshalFromFile(t *testing.T) {
	// Read the actual issuer_metadata.json file
	metadataPath := filepath.Join("..", "..", "metadata", "issuer_metadata.json")
	data, err := os.ReadFile(metadataPath)
	require.NoError(t, err, "Failed to read issuer_metadata.json")

	// Unmarshal into our Go struct
	var metadata CredentialIssuerMetadataParameters
	err = json.Unmarshal(data, &metadata)
	require.NoError(t, err, "Failed to unmarshal issuer_metadata.json into CredentialIssuerMetadataParameters")

	// Validate required fields
	t.Run("Required Fields", func(t *testing.T) {
		assert.NotEmpty(t, metadata.CredentialIssuer, "credential_issuer is required")
		assert.Equal(t, "http://vc_dev_apigw:8080", metadata.CredentialIssuer)

		assert.NotEmpty(t, metadata.CredentialEndpoint, "credential_endpoint is required")
		assert.Equal(t, "http://vc_dev_apigw:8080/credential", metadata.CredentialEndpoint)

		assert.NotEmpty(t, metadata.CredentialConfigurationsSupported, "credential_configurations_supported is required")
		assert.Len(t, metadata.CredentialConfigurationsSupported, 4, "Expected 4 credential configurations")
	})

	// Validate display properties
	t.Run("Display Properties", func(t *testing.T) {
		assert.Len(t, metadata.Display, 1, "Expected 1 display entry")
		assert.Equal(t, "SUNET dev Issuer (vc project)", metadata.Display[0].Name)
		assert.Equal(t, "en-US", metadata.Display[0].Locale)
	})

	// Validate credential configurations
	t.Run("Credential Configurations", func(t *testing.T) {
		expectedConfigs := []string{
			"urn:edui:diploma:1",
			"urn:eudi:pid:1",
			"urn:eudi:ehic:1",
			"urn:eudi:pda1:1",
		}

		for _, configID := range expectedConfigs {
			t.Run(configID, func(t *testing.T) {
				config, exists := metadata.CredentialConfigurationsSupported[configID]
				require.True(t, exists, "Configuration %s should exist", configID)

				// Validate format
				assert.Equal(t, "dc+sd-jwt", config.Format, "All credentials should use dc+sd-jwt format")

				// Validate scope
				assert.NotEmpty(t, config.Scope, "Scope should not be empty")

				// Validate VCT
				assert.NotEmpty(t, config.VCT, "VCT should not be empty")

				// Validate cryptographic binding methods
				assert.Contains(t, config.CryptographicBindingMethodsSupported, "jwk",
					"Should support jwk binding method")

				// Validate signing algorithms
				assert.Contains(t, config.CredentialSigningAlgValuesSupported, "ES256",
					"Should support ES256 signing algorithm")

				// Validate proof types
				assert.NotEmpty(t, config.ProofTypesSupported, "Proof types should not be empty")
				jwtProof, hasJWT := config.ProofTypesSupported["jwt"]
				require.True(t, hasJWT, "Should support jwt proof type")
				assert.Contains(t, jwtProof.ProofSigningAlgValuesSupported, "ES256",
					"JWT proof should support ES256")

				// Validate display
				assert.NotEmpty(t, config.Display, "Display should not be empty")
				assert.NotEmpty(t, config.Display[0].Name, "Display name should not be empty")
				assert.NotEmpty(t, config.Display[0].Locale, "Display locale should not be empty")
			})
		}
	})

	// Validate specific credential configurations
	t.Run("Diploma Configuration", func(t *testing.T) {
		diploma, exists := metadata.CredentialConfigurationsSupported["urn:edui:diploma:1"]
		require.True(t, exists)

		assert.Equal(t, "diploma", diploma.Scope)
		assert.Equal(t, "urn:eudi:diploma:1", diploma.VCT)
		assert.Equal(t, "Bachelor Diploma - SD-JWT VC", diploma.Display[0].Name)
		assert.NotEmpty(t, diploma.Display[0].Logo.URI)
		assert.Equal(t, "#b1d3ff", diploma.Display[0].BackgroundColor)
		assert.Equal(t, "#ffffff", diploma.Display[0].TextColor)
	})

	t.Run("PID Configuration", func(t *testing.T) {
		pid, exists := metadata.CredentialConfigurationsSupported["urn:eudi:pid:1"]
		require.True(t, exists)

		assert.Equal(t, "pid", pid.Scope)
		assert.Equal(t, "urn:eudi:pid:1", pid.VCT)
		assert.Equal(t, "PID SD-JWT VC ARF 1.5", pid.Display[0].Name)
		assert.Equal(t, "Person Identification Data", pid.Display[0].Description)
		assert.NotEmpty(t, pid.Display[0].BackgroundImage.URI)
		assert.Equal(t, "#1b263b", pid.Display[0].BackgroundColor)
		assert.Equal(t, "#FFFFFF", pid.Display[0].TextColor)
	})

	t.Run("EHIC Configuration", func(t *testing.T) {
		ehic, exists := metadata.CredentialConfigurationsSupported["urn:eudi:ehic:1"]
		require.True(t, exists)

		assert.Equal(t, "ehic", ehic.Scope)
		assert.Equal(t, "urn:eudi:ehic:1", ehic.VCT)
		assert.Equal(t, "EHIC - SD-JWT VC", ehic.Display[0].Name)
		assert.Equal(t, "European Health Insurance Card", ehic.Display[0].Description)
	})

	t.Run("PDA1 Configuration", func(t *testing.T) {
		pda1, exists := metadata.CredentialConfigurationsSupported["urn:eudi:pda1:1"]
		require.True(t, exists)

		assert.Equal(t, "ehic", pda1.Scope) // Note: in the JSON it's "ehic" not "pda1"
		assert.Equal(t, "urn:eudi:pda1:1", pda1.VCT)
		assert.Equal(t, "EHIC - SD-JWT VC", pda1.Display[0].Name)
		assert.Equal(t, "European Portable Document Application", pda1.Display[0].Description)
	})
}

func TestCredentialIssuerMetadataParameters_MarshalRoundTrip(t *testing.T) {
	// Read original JSON
	metadataPath := filepath.Join("..", "..", "metadata", "issuer_metadata.json")
	originalData, err := os.ReadFile(metadataPath)
	require.NoError(t, err)

	// Unmarshal into struct
	var metadata CredentialIssuerMetadataParameters
	err = json.Unmarshal(originalData, &metadata)
	require.NoError(t, err)

	// Marshal back to JSON
	marshaledData, err := json.Marshal(&metadata)
	require.NoError(t, err)

	// Unmarshal both to maps for comparison (to ignore field ordering)
	var originalMap map[string]interface{}
	var marshaledMap map[string]interface{}

	err = json.Unmarshal(originalData, &originalMap)
	require.NoError(t, err)

	err = json.Unmarshal(marshaledData, &marshaledMap)
	require.NoError(t, err)

	// Compare key fields
	assert.Equal(t, originalMap["credential_issuer"], marshaledMap["credential_issuer"])
	assert.Equal(t, originalMap["credential_endpoint"], marshaledMap["credential_endpoint"])

	// Verify credential configurations are preserved
	originalConfigs := originalMap["credential_configurations_supported"].(map[string]interface{})
	marshaledConfigs := marshaledMap["credential_configurations_supported"].(map[string]interface{})
	assert.Equal(t, len(originalConfigs), len(marshaledConfigs), "Should have same number of configurations")
}

func TestCredentialIssuerMetadataParameters_OpenID4VCI_Compliance(t *testing.T) {
	metadataPath := filepath.Join("..", "..", "metadata", "issuer_metadata.json")
	data, err := os.ReadFile(metadataPath)
	require.NoError(t, err)

	var metadata CredentialIssuerMetadataParameters
	err = json.Unmarshal(data, &metadata)
	require.NoError(t, err)

	t.Run("Section 12.2.4 - Required Parameters", func(t *testing.T) {
		// credential_issuer: REQUIRED
		assert.NotEmpty(t, metadata.CredentialIssuer,
			"credential_issuer is REQUIRED per Section 12.2.4")

		// credential_endpoint: REQUIRED
		assert.NotEmpty(t, metadata.CredentialEndpoint,
			"credential_endpoint is REQUIRED per Section 12.2.4")

		// credential_configurations_supported: REQUIRED
		assert.NotEmpty(t, metadata.CredentialConfigurationsSupported,
			"credential_configurations_supported is REQUIRED per Section 12.2.4")
	})

	t.Run("Section 12.2.4 - Optional Parameters", func(t *testing.T) {
		// These should be allowed to be empty/nil since they're OPTIONAL
		// Just verify the fields exist and can be accessed
		_ = metadata.AuthorizationServers
		_ = metadata.DeferredCredentialEndpoint
		_ = metadata.NotificationEndpoint
		_ = metadata.CredentialResponseEncryption
		_ = metadata.BatchCredentialIssuance
		_ = metadata.SignedMetadata
		_ = metadata.Display
	})

	t.Run("Credential Format - SD-JWT VC", func(t *testing.T) {
		// All credentials in the file use dc+sd-jwt format
		for configID, config := range metadata.CredentialConfigurationsSupported {
			assert.Equal(t, "dc+sd-jwt", config.Format,
				"Configuration %s should use dc+sd-jwt format per Appendix A.3", configID)

			// For SD-JWT VC format, vct parameter should be present
			assert.NotEmpty(t, config.VCT,
				"Configuration %s should have vct parameter for dc+sd-jwt format", configID)
		}
	})

	t.Run("Cryptographic Binding Methods", func(t *testing.T) {
		for configID, config := range metadata.CredentialConfigurationsSupported {
			assert.NotEmpty(t, config.CryptographicBindingMethodsSupported,
				"Configuration %s should specify cryptographic binding methods", configID)

			// Validate that binding methods are recognized values
			for _, method := range config.CryptographicBindingMethodsSupported {
				assert.Contains(t, []string{"jwk", "cose_key"}, method,
					"Configuration %s has unrecognized binding method: %s", configID, method)
			}
		}
	})

	t.Run("Proof Types", func(t *testing.T) {
		for configID, config := range metadata.CredentialConfigurationsSupported {
			assert.NotEmpty(t, config.ProofTypesSupported,
				"Configuration %s should specify proof types", configID)

			// Validate proof_signing_alg_values_supported is present for each proof type
			for proofType, proofSpec := range config.ProofTypesSupported {
				assert.NotEmpty(t, proofSpec.ProofSigningAlgValuesSupported,
					"Configuration %s proof type %s should have proof_signing_alg_values_supported",
					configID, proofType)
			}
		}
	})

	t.Run("Display Properties", func(t *testing.T) {
		// Issuer-level display
		if len(metadata.Display) > 0 {
			for _, display := range metadata.Display {
				if display.Locale != "" {
					// Locale should be BCP47 compliant (basic check)
					assert.Regexp(t, `^[a-z]{2}(-[A-Z]{2})?$`, display.Locale,
						"Locale should be BCP47 compliant")
				}
			}
		}

		// Credential-level display
		for configID, config := range metadata.CredentialConfigurationsSupported {
			if len(config.Display) > 0 {
				assert.NotEmpty(t, config.Display[0].Name,
					"Configuration %s display should have a name", configID)

				if config.Display[0].Locale != "" {
					assert.Regexp(t, `^[a-z]{2}(-[A-Z]{2})?$`, config.Display[0].Locale,
						"Configuration %s display locale should be BCP47 compliant", configID)
				}
			}
		}
	})
}

func TestCredentialConfigurationsSupported_StructureCompliance(t *testing.T) {
	metadataPath := filepath.Join("..", "..", "metadata", "issuer_metadata.json")
	data, err := os.ReadFile(metadataPath)
	require.NoError(t, err)

	var metadata CredentialIssuerMetadataParameters
	err = json.Unmarshal(data, &metadata)
	require.NoError(t, err)

	for configID, config := range metadata.CredentialConfigurationsSupported {
		t.Run(configID, func(t *testing.T) {
			// format: REQUIRED
			assert.NotEmpty(t, config.Format, "format is REQUIRED")

			// For dc+sd-jwt format:
			if config.Format == "dc+sd-jwt" {
				// vct should be present (Appendix A.3.2)
				assert.NotEmpty(t, config.VCT, "vct should be present for dc+sd-jwt format")
			}

			// scope: OPTIONAL but present in our metadata
			if config.Scope != "" {
				assert.NotEmpty(t, config.Scope, "scope should not be empty string")
			}

			// cryptographic_binding_methods_supported: OPTIONAL
			// credential_signing_alg_values_supported: OPTIONAL
			// proof_types_supported: OPTIONAL but should be present if cryptographic binding is used

			// If cryptographic binding is specified, proof types should be too
			if len(config.CryptographicBindingMethodsSupported) > 0 {
				assert.NotEmpty(t, config.ProofTypesSupported,
					"proof_types_supported should be present when cryptographic binding is used")
			}
		})
	}
}
