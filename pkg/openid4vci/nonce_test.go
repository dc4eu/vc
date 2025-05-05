package openid4vci

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateNonce(t *testing.T) {
	tts := []struct {
		name string
		size int
		want int
	}{
		{
			name: "lower limit",
			size: 0,
			want: 44,
		},
		{
			name: "16",
			size: 16,
			want: 24,
		},
		{
			name: "94",
			size: 94,
			want: 128,
		},
		{
			name: "upper limit",
			size: 10000,
			want: 128,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateNonce(tt.size)
			assert.NoError(t, err)

			assert.Equal(t, tt.want, len(got))
			t.Log(got)
		})
	}
}
