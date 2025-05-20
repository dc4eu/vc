package apiv1

import (
	"bytes"
	"context"
	"testing"
	"vc/pkg/logger"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

var nonRandom = bytes.NewReader([]byte("01234567890123456789012345678901234567890123456789ABCDEF"))

// Sometimes this test does not behave deterministically
func TestCreateJWK(t *testing.T) {
	tts := []struct {
		name string
		want jwt.MapClaims
	}{
		{
			name: "Test 1",
			want: jwt.MapClaims{
				"jwk": jwt.MapClaims{
					"crv": "P-256",
					"kid": "default_signing_key_id",
					"kty": "EC",
					"d":   "MjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM",
					"x":   "kVao_jC0orUqlfq6lIEMgxE7mkTKQvrx28Gs7c50jeo",
					"y":   "47JXwoQzMH8_0rC72HAZPWWqsSHZPHniugPjuE03BEM",
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()
			client := mockNewClient(ctx, t, "ecdsa", logger.NewSimple("testing_apiv1"))

			err := client.createJWK(context.Background())
			assert.NoError(t, err)

			if diff := cmp.Diff(tt.want, client.jwkClaim); diff != "" {
				t.Errorf("diff: mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
