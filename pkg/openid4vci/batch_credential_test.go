package openid4vci

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

func TestBatchCredentialResponse(t *testing.T) {
	tests := []struct {
		name       string
		goldenFile string
		want       *BatchCredentialResponse
	}{
		{
			name:       "fat credential response",
			goldenFile: "batch_credential_response.golden",
			want: &BatchCredentialResponse{
				CredentialResponses: []CredentialResponse{
					{
						Credential: "eyJraWQiOiJkaWQ6ZXhhbXBsZTpl...C_aZKPxgihac0aW9EkL1nOzM",
					},
					{
						Credential: "YXNkZnNhZGZkamZqZGFza23....29tZTIzMjMyMzIzMjMy",
					},
				},
				CNonce:          "fGFF7UkhLa",
				CNonceExpiresIn: 86400,
			},
		},
		{
			name:       "deferred credential response",
			goldenFile: "batch_credential_response_deferred.golden",
			want: &BatchCredentialResponse{
				CredentialResponses: []CredentialResponse{
					{
						TransactionID: "8xLOxBtZp8",
					},
					{
						Credential: "YXNkZnNhZGZkamZqZGFza23....29tZTIzMjMyMzIzMjMy",
					},
				},
				CNonce:          "fGFF7UkhLa",
				CNonceExpiresIn: 86400,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := golden.Get(t, tt.goldenFile)

			got := &BatchCredentialResponse{}
			err := json.Unmarshal(g, got)
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}
