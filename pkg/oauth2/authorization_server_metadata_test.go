package oauth2

import (
	"crypto/ecdsa"
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

var mockAuthorizationServerMetadata = &AuthorizationServerMetadata{
	Issuer:                              "http://vc_dev_apigw:8080",
	AuthorizationEndpoint:               "http://vc_dev_apigw:8080/authorize",
	TokenEndpoint:                       "http://vc_dev_apigw:8080/token",
	ResponseTypesSupported:              []string{"code"},
	TokenEndpointAuthMethodsSupported:   []string{"none"},
	CodeChallengeMethodsSupported:       []string{"S256"},
	PushedAuthorizationRequestEndpoint:  "http://vc_dev_apigw:8080/par",
	RequiredPushedAuthorizationRequests: true,
	DPOPSigningALGValuesSupported:       []string{"ES256"},
}

func TestMarshalMetadata(t *testing.T) {
	tts := []struct {
		name           string
		goldenFileName string
		signedMetadata string
		want           *AuthorizationServerMetadata
	}{
		{
			name:           "test",
			goldenFileName: "metadata_json.golden",
			want:           mockAuthorizationServerMetadata,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			fileByte := golden.Get(t, tt.goldenFileName)

			got := &AuthorizationServerMetadata{}
			err := json.Unmarshal(fileByte, got)
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSignMetadata(t *testing.T) {
	tts := []struct {
		name           string
		issuerMetadata *AuthorizationServerMetadata
	}{
		{
			name:           "test",
			issuerMetadata: mockAuthorizationServerMetadata,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			metadata := tt.issuerMetadata

			signingKey, cert := mockGenerateECDSAKey(t)
			pubKey := signingKey.(*ecdsa.PrivateKey).Public()

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
