package jose

import (
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestMakeJWT(t *testing.T) {
	tts := []struct {
		name          string
		header        jwt.MapClaims
		body          jwt.MapClaims
		signingMethod jwt.SigningMethod
	}{
		{
			name: "test1",
			header: jwt.MapClaims{
				"alg": "ES256",
				"typ": "openid4vci-proof+jwt",
				"kid": "key-1",
			},
			body: jwt.MapClaims{
				"iss":   "joe",
				"aud":   "https://example.com",
				"iat":   1300819380,
				"nonce": "n-0S6_WzA2Mj",
			},
			signingMethod: jwt.SigningMethodES256,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			jwk, privateKey, err := CreateJWK("../../developer_tools/private_ec256.pem")
			assert.NoError(t, err)

			tt.body["jwk"] = jwk

			signedToken, err := MakeJWT(tt.header, tt.body, tt.signingMethod, privateKey)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Println("signedToken", signedToken)
		})
	}
}
