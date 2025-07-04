package oauth2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateCryptographicNonceWithLength(t *testing.T) {
	tts := []struct {
		name string
		n    int
		want int
	}{
		{
			name: "Generate 32 character nonce",
			n:    32,
			want: 32,
		},
		{
			name: "Generate 100 character nonce",
			n:    100,
			want: 52,
		},
		{
			name: "Generate 100 character nonce",
			n:    0,
			want: 52,
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateCryptographicNonceFixedLength(tt.n)
			fmt.Println("Generated nonce:", got)

			assert.Equal(t, tt.want, len(got))
		})
	}
}
