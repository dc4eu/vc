package model

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenericUploadTestv1JSON(t *testing.T) {
	tts := []struct {
		name string
		have *UploadDocument
		want string
	}{
		{
			name: "testv1",
			have: &UploadDocument{},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.MarshalIndent(tt.have, "", "  ")
			assert.NoError(t, err)
			fmt.Println(string(got))
		})
	}
}
