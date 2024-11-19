package parisusers

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestXLS(t *testing.T) {

	t.Run("ehic", func(t *testing.T) {
		ehic := EHIC("testdata/users_paris.xlsx")
		jsonBytes, err := json.MarshalIndent(ehic, "", "  ")
		assert.NoError(t, err)
		t.Log(string(jsonBytes))
	})

	t.Run("pda1", func(t *testing.T) {
		pda1ar := PDA1("testdata/users_paris.xlsx")
		jsonBytes, err := json.MarshalIndent(pda1ar, "", "  ")
		assert.NoError(t, err)
		t.Log(string(jsonBytes))
	})
}

func TestMake(t *testing.T) {
	storage := Make("testdata/users_paris.xlsx")

	assert.Len(t, storage, 160)
}
