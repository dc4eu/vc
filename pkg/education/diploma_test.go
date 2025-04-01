package education

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

func TestDiplomaMarshal(t *testing.T) {
	tts := []struct {
		name string
		have *DiplomaDocument
		want string
	}{
		{
			name: "success",
			have: &DiplomaDocument{},
			want: "diploma.golden",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.have.Marshal()
			assert.NoError(t, err)

			want := golden.Get(t, tt.want)

			wantMap := map[string]any{}
			err = json.Unmarshal(want, &wantMap)
			assert.NoError(t, err)

			assert.Equal(t, wantMap, got)
		})
	}
}

func TestDiplomaCredential(t *testing.T) {
	tts := []struct {
		name  string
		abort bool
	}{
		{
			name:  "1.json",
			abort: false,
		},
		{
			name:  "2.json",
			abort: true,
		},
		{
			name:  "3.json",
			abort: true,
		},
		{
			name:  "4.json",
			abort: true,
		},
		{
			name:  "5.json",
			abort: true,
		},
		{
			name:  "6.json",
			abort: true,
		},
		{
			name:  "7.json",
			abort: true,
		},
		{
			name:  "8.json",
			abort: true,
		},
		{
			name:  "9.json",
			abort: true,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			if tt.abort {
				t.SkipNow()
			}
			f, err := os.ReadFile(fmt.Sprintf("../../standards/education_credential/diploma/%s", tt.name))
			assert.NoError(t, err)

			doc := &DiplomaDocument{}
			if err := json.Unmarshal(f, doc); err != nil {
				t.Fatal(err)
			}

			diploma := NewDiploma()

			assert.Equal(t, doc, diploma)
		})
	}
}
