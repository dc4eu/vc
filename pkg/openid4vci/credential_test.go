package openid4vci

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCredentialValidation(t *testing.T) {
	tts := []struct {
		name              string
		credentialRequest *CredentialRequest
		tokenResponse     *TokenResponse
		want              error
	}{
		{
			name: "test",
			credentialRequest: &CredentialRequest{
				Format: "vc+ldp",
			},
			tokenResponse: &TokenResponse{
				AccessToken:     "",
				TokenType:       "",
				ExpiresIn:       0,
				Scope:           "",
				State:           "",
				CNonce:          "",
				CNonceExpiresIn: 0,
				AuthorizationDetails: []AuthorizationDetailsParameter{
					{
						Type:                      "",
						CredentialConfigurationID: "vc+ldp",
						Format:                    "",
						VCT:                       "",
						Claims:                    map[string]any{},
					},
				},
			},
			want: nil,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()
			got := tt.credentialRequest.Validate(ctx, tt.tokenResponse)
			assert.NoError(t, got)
		})
	}
}
