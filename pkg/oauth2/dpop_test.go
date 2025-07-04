package oauth2

import (
	"testing"
	"vc/internal/gen/issuer/apiv1_issuer"

	"github.com/stretchr/testify/assert"
)

var mockJWT_1 = `eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiZXdpYlNCaC1uVDgwdVJuQ0lfX0t6bkVXOXN6b0RhMDI3YU1kdjJOb3RRcyIsInkiOiJIUlpyYml0dmZmNTk3WXBUV0F1d2d5ZHk3cWpsTGRaNjNuMHFwaW5PbGxFIn19.eyJqdGkiOiI4NGJiMzI2NmNjZDZhYmY4IiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vdmMtaW50ZXJvcC0zLnN1bmV0LnNlL3Rva2VuIiwiaWF0IjoxNzQ4MzM1NTU0fQ.HuAKEiFm6CGFLTWJvf0Ll8Cj9vcltsJ1ThgBqhttuV3diE1lkeJO6QzO-h_F0fes1rm6HqRhDLwhW34SxXK4Eg`
var mockJWK_1 = `{
    "kty": "EC",
    "crv": "P-256",
    "x": "ewibSBh-nT80uRnCI__KznEW9szoDa027aMdv2NotQs",
    "y": "HRZrbitvff597YpTWAuwgydy7qjlLdZ63n0qpinOllE",
	"kid": "key-1"
  }`

var mockJWT_2 = `eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiVl9DSjdmckhmNWlITU1rclI0TDlPVzhRbEFYOE5Ibnk2ZFgxSWxqcloyOCIsInkiOiJ0R3ByVWE1SFg4aERzQlZXd1RIcEhjc3hjZDFqaGN0Ql9ULTZtZzRXLU5nIn19.eyJqdGkiOiJiN2JlNmNkYThkNDIwNjk5IiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vdmMtaW50ZXJvcC0zLnN1bmV0LnNlL3Rva2VuIiwiaWF0IjoxNzQ4MzUzNDgyfQ.MTldxLq3g1g8yzLikj74n_HldPSfwbw_A-9Ut1mf_IIjqqj0SAkTAdlyOqXu9AuPlH5Baz4ZAS5mK_RxGdN4Tg`
var mockJWK_2 = `{
    "crv": "P-256",
    "kty": "EC",
    "x": "V_CJ7frHf5iHMMkrR4L9OW8QlAX8NHny6dX1IljrZ28",
    "y": "tGprUa5HX8hDsBVWwTHpHcsxcd1jhctB_T-6mg4W-Ng"
  }`

func TestParseJWK(t *testing.T) {
	tts := []struct {
		name        string
		jwk         string
		fingerprint string
	}{
		{
			name:        "mockJWK_1",
			jwk:         mockJWK_1,
			fingerprint: "ddd7868c9fd1c0a718f13586206dd47e551fdc1b16bd2ad053e5bf09651392fd",
		},
		{
			name:        "mockJWK_2",
			jwk:         mockJWK_2,
			fingerprint: "9b85a44324a33a89d650d9aef4b3c85d7ae24bbd07ec062322d956e1b82593ff",
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			key, fingerprint, err := parseDpopJWK([]byte(tt.jwk))
			assert.Equal(t, tt.fingerprint, fingerprint, "fingerprint should match expected value")
			assert.NoError(t, err, "parseJWK should not return an error")
			assert.NotNil(t, key, "key should not be nil")
		})
	}
}

func TestValidate(t *testing.T) {
	tts := []struct {
		name string
		jwt  string
		jwk  string
		want *DPoP
	}{
		{
			name: "mockJWT_1",
			jwt:  mockJWT_1,
			want: &DPoP{
				JTI:        "",
				HTM:        "",
				HTU:        "",
				ATH:        "",
				Thumbprint: "",
				JWK: &apiv1_issuer.Jwk{
					Crv: "P-256",
					Kty: "EC",
					X:   "V_CJ7frHf5iHMMkrR4L9OW8QlAX8NHny6dX1IljrZ28",
					Y:   "tGprUa5HX8hDsBVWwTHpHcsxcd1jhctB_T-6mg4W-Ng",
				},
			},
		},
		{
			name: "mockJWT_2",
			jwt:  mockJWT_2,
			want: nil,
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateAndParseDPoPJWT(tt.jwt)
			assert.NoError(t, err, "ValidateAndParseDPoPJWT should not return an error")

			assert.Equal(t, tt.want, got, "Parsed DPoP should match expected value")
			//assert.Equal(t, tt.want, err, "Error should match expected error")
		})
	}
}
