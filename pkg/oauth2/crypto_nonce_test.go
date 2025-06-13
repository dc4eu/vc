package oauth2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateCryptographicNonce(t *testing.T) {
	tts := []struct {
		name string
		n    int
		want int
	}{
		{
			name: "Generate 16 byte nonce",
			n:    16,
			want: 24,
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateCryptographicNonce(tt.n)
			assert.NoError(t, err)

			fmt.Println("Generated nonce:", got)

			assert.Equal(t, tt.want, len(got))
		})
	}
}

func TestGenerateCryptographicNonceWithLength(t *testing.T) {
	tts := []struct {
		name string
		n    int
		want int
	}{
		{
			name: "Generate 32 byte nonce",
			n:    32,
			want: 32,
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateCryptographicNonceWithLength(tt.n)

			assert.Equal(t, tt.want, len(got))
		})
	}
}
