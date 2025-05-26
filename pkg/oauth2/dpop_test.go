package oauth2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// var mockDPoPJWT = `eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiY29zREY4NXhqTWZ5V2F2ZE96TVMzUVhRRmpIVGVTM003Vk9HeWFXOVZJayIsInkiOiI2QVNta0Q5d1JObXRsYTVxSjdhbEZEOUFjbTk4Y3NtUHJmXzhfWnhPNTF3In19.eyJqdGkiOiIxMTU2ZTExNDlkMTcxNzg4IiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vdmMtaW50ZXJvcC0zLnN1bmV0LnNlL3Rva2VuIiwiaWF0IjoxNzQ3NzUzNDI5fQ.ItiSaldkATeXDtFfmMac1lVEZgsrjOrA6hLS9fBrE0RBy5nKeA62nFg_tLFb126VdVf6rha3cHPkkssoPiOfCg`
var mockDPoPJWT = `eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiNlh4SXlVSVBQZG9DSWtIekhNT3A2YXpGckxEdktxRGdMZ2hTbEhPNGE1SSIsInkiOiJXZlZLN2x2OGRvMjc1UElrcF9KRklzRlVTSVR0YmNpY0NwOTRYb3FoTXpJIn19.eyJqdGkiOiI2N2U0OTQ0MjAxYjdmNDg1IiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vdmMtaW50ZXJvcC0zLnN1bmV0LnNlL3Rva2VuIiwiaWF0IjoxNzQ4MDA1MjA5fQ.6tm3TZ_ucRBgiC2FtZOco5kiR6rLZotANd1FPoUI_aUJYE5H9mf4gV29T8SzOXgJ_supSN4c9Gf-LAhM-iqSxA`
var mockDPoPJWT_2 = `eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiNlh4SXlVSVBQZG9DSWtIekhNT3A2YXpGckxEdktxRGdMZ2hTbEhPNGE1SSIsInkiOiJXZlZLN2x2OGRvMjc1UElrcF9KRklzRlVTSVR0YmNpY0NwOTRYb3FoTXpJIn19.eyJqdGkiOiI2N2U0OTQ0MjAxYjdmNDg1IiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vdmMtaW50ZXJvcC0zLnN1bmV0LnNlL3Rva2VuIiwiaWF0IjoxNzQ4MDA1MjA5fQ.6tm3TZ_ucRBgiC2FtZOco5kiR6rLZotANd1FPoUI_aUJYE5H9mf4gV29T8SzOXgJ_supSN4c9Gf-LAhM-iqSxA`
var mockJWK = `{
        "crv": "P-256",
        "kty": "EC",
        "x": "6XxIyUIPPdoCIkHzHMOp6azFrLDvKqDgLghSlHO4a5I",
        "y": "WfVK7lv8do275PIkp_JFIsFUSITtbcicCp94XoqhMzI"
} `

func TestParseJWK(t *testing.T) {
	k, err := parseJWK(mockJWK)
	fmt.Println("k", k)
	fmt.Println("err", err)
}

func TestValidate(t *testing.T) {
	keySet, err := parseJWK(mockJWK)
	assert.NoError(t, err)

	Validate(mockDPoPJWT, keySet)
}

//func TestParseDPoP(t *testing.T) {
//	// Test cases
//	tests := []struct {
//		name  string
//		input string
//		want  *DPoP
//	}{
//		{
//			name:  "valid DPoP",
//			input: mockDPoPJWT,
//			want: &DPoP{
//				JTI: "12345",
//				HTM: "POST",
//				HTU: "https://example.com",
//				ATH: "abc123",
//			},
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			privKey, _ := mockGenerateECDSAKey(t)
//
//			pubKey := privKey.(*ecdsa.PrivateKey).Public()
//
//			got, err := ParseDPoPJWT(tt.input, pubKey)
//			assert.NoError(t, err)
//
//			assert.Equal(t, tt.want, got)
//		})
//	}
//}

//func TestDPoPSign(t *testing.T) {
//	// Test cases
//	tests := []struct {
//		name  string
//		input *DPoP
//	}{
//		{
//			name: "valid DPoP",
//			input: &DPoP{
//				JTI: "12345",
//				HTM: "POST",
//				HTU: "https://example.com",
//				ATH: "abc123",
//			},
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			privKey, _ := mockGenerateECDSAKey(t)
//
//			//pubKey := privKey.(*ecdsa.PrivateKey).Public()
//
//			got, err := tt.input.SignJWT(jwt.SigningMethodES256, privKey, nil)
//			assert.NoError(t, err)
//
//			assert.NotEmpty(t, got)
//			fmt.Println("got", got)
//		})
//	}
//}
