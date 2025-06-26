package openid4vp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthorizationRequest(t *testing.T) {
	tts := []struct {
		name     string
		wantPath string
		have     *AuthorizationRequest_v2
	}{
		{
			name:     "Valid Request",
			wantPath: "authorization_request_jwt_body",
			have:     &AuthorizationRequest_v2{},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, err := tt.have.Marshal()
			assert.NoError(t, err, "Marshal should not return an error")
			if gotPath != tt.wantPath {
				t.Errorf("GetPath() = %v, want %v", gotPath, tt.wantPath)
			}
		})
	}
}
