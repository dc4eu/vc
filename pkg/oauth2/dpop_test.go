package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var mockDPoPJWT = `eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiY29zREY4NXhqTWZ5V2F2ZE96TVMzUVhRRmpIVGVTM003Vk9HeWFXOVZJayIsInkiOiI2QVNta0Q5d1JObXRsYTVxSjdhbEZEOUFjbTk4Y3NtUHJmXzhfWnhPNTF3In19.eyJqdGkiOiIxMTU2ZTExNDlkMTcxNzg4IiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vdmMtaW50ZXJvcC0zLnN1bmV0LnNlL3Rva2VuIiwiaWF0IjoxNzQ3NzUzNDI5fQ.ItiSaldkATeXDtFfmMac1lVEZgsrjOrA6hLS9fBrE0RBy5nKeA62nFg_tLFb126VdVf6rha3cHPkkssoPiOfCg`

func TestParseDPoP(t *testing.T) {
	// Test cases
	tests := []struct {
		name  string
		input string
		want  *DPoP
	}{
		{
			name:  "valid DPoP",
			input: mockDPoPJWT,
			want: &DPoP{
				JTI: "12345",
				HTM: "POST",
				HTU: "https://example.com",
				ATH: "abc123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAndValidateDPoPJWT(tt.input)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
