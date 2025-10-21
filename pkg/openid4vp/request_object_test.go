package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

func TestAuthorizationRequest(t *testing.T) {
	tts := []struct {
		name       string
		goldenPath string
	}{
		{
			name:       "Valid Request",
			goldenPath: "request_object_from_spec.json",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			want := golden.Get(t, tt.goldenPath)

			mura := &RequestObject{}
			err := json.Unmarshal(want, &mura)
			assert.NoError(t, err, "Unmarshal should not return an error")

			got, err := json.Marshal(mura)
			assert.NoError(t, err, "Marshal should not return an error")

			assert.JSONEq(t, string(want), string(got), "JSON output should match golden file")
		})
	}
}
