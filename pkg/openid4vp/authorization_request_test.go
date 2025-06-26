package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

func TestAuthorizationRequest(t *testing.T) {
	tts := []struct {
		name     string
		wantPath string
		have     *AuthorizationRequest_v2
	}{
		{
			name:     "Valid Request",
			wantPath: "authorization_request_jwt_body.golden",
			have:     &AuthorizationRequest_v2{},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			want := golden.Get(t, tt.wantPath)

			err := json.Unmarshal(want, tt.have)
			assert.NoError(t, err, "Unmarshal should not return an error")

			got, err := tt.have.Marshal()
			assert.NoError(t, err, "Marshal should not return an error")

			assert.JSONEq(t, string(want), string(got), "JSON output should match golden file")

		})
	}
}
