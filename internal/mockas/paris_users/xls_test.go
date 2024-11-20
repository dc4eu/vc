package parisusers

import (
	"encoding/json"
	"fmt"
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

func TestCSV(t *testing.T) {
	storage := Make("testdata/users_paris.xlsx")
	csv, _, err := CSV(storage)
	assert.NoError(t, err)

	fmt.Printf("\nauthentic_source_person_id,given_name,family_name,birth_date,identity schema name,authentic_source,collect_id,document_type\n")
	fmt.Printf("%v", csv)

}

func TestSaveCSVToDisk(t *testing.T) {
	storage := Make("testdata/users_paris.xlsx")
	_, records, err := CSV(storage)
	assert.NoError(t, err)

	err = saveCSVToDisk(records, "../../../users_paris.csv")
	assert.NoError(t, err)
}
