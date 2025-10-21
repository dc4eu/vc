package openid4vci

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

// mockLoadVCTM is a convenience function to load a VCTM from a golden file.
func mockLoadVCTM(t *testing.T, vctmPath string) *VCTM {
	t.Helper()

	data := golden.Get(t, vctmPath)
	var vctm *VCTM
	err := json.Unmarshal(data, &vctm)
	assert.NoError(t, err)

	return vctm
}

func TestVCTM(t *testing.T) {
	tts := []struct {
		name       string
		goldenPath string
	}{
		{
			name:       "empty",
			goldenPath: "vctm_pid.json",
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			want := golden.Get(t, tt.goldenPath)

			vctm := mockLoadVCTM(t, tt.goldenPath)

			got, err := json.MarshalIndent(vctm, "", "  ")
			assert.NoError(t, err)

			assert.JSONEq(t, string(want), string(got))
		})
	}
}

func TestVCTMValidate(t *testing.T) {
	tts := []struct {
		name       string
		goldenPath string
		want       error
	}{
		{
			name:       "valid",
			goldenPath: "vctm_pid.json",
			want:       nil,
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			vctm := mockLoadVCTM(t, tt.goldenPath)

			got := vctm.Validate()

			assert.Equal(t, tt.want, got)
		})
	}
}
