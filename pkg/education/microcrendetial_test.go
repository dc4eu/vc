package education

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMicroCredentials(t *testing.T) {
	tts := []struct {
		name  string
		abort bool
	}{
		{
			name: "mbob_eo_eov_microcredential_full.json",
		},
		{
			name: "mbob_ht_pf_microcredential_full.json",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			if tt.abort {
				t.SkipNow()
			}
			f, err := os.ReadFile(fmt.Sprintf("../../standards/education_credential/micro_credential/%s", tt.name))
			assert.NoError(t, err)

			doc := &MicroCredentialDocument{}
			err = json.Unmarshal(f, doc)
			assert.NoError(t, err)

			//diploma := NewDiploma()

			//assert.Equal(t, doc, diploma)
		})
	}
}
