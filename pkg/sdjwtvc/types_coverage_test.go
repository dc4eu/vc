package sdjwtvc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVCTM_Attributes(t *testing.T) {
	label1 := "Name"
	label2 := "Email"
	name := "name"
	email := "email"

	vctm := &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&name},
				Display: []ClaimDisplay{
					{
						Lang:  "en",
						Label: label1,
					},
					{
						Lang:  "fr",
						Label: "Nom",
					},
				},
			},
			{
				Path: []*string{&email},
				Display: []ClaimDisplay{
					{
						Lang:  "en",
						Label: label2,
					},
				},
			},
		},
	}

	attrs := vctm.Attributes()

	assert.NotNil(t, attrs)
	assert.Contains(t, attrs, "en")
	assert.Contains(t, attrs, "fr")

	assert.Contains(t, attrs["en"], label1)
	assert.Contains(t, attrs["en"], label2)
	assert.Equal(t, []string{"name"}, attrs["en"][label1])
	assert.Equal(t, []string{"email"}, attrs["en"][label2])

	assert.Contains(t, attrs["fr"], "Nom")
	assert.Equal(t, []string{"name"}, attrs["fr"]["Nom"])
}

func TestVCTM_Attributes_RealMetadata(t *testing.T) {
	metadataDir := "../../metadata"
	
	testCases := []struct {
		filename        string
		expectedLangs   []string
		expectedLabels  map[string][]string // language -> list of labels
		samplePathCheck map[string]string   // label -> expected path (first one)
	}{
		{
			filename:      "vctm_pid_arf_1_8.json",
			expectedLangs: []string{"en-US"},
			expectedLabels: map[string][]string{
				"en-US": {"Last name", "First name", "Date of birth", "Nationality"},
			},
			samplePathCheck: map[string]string{
				"Last name":     "family_name",
				"First name":    "given_name",
				"Date of birth": "birthdate", // Note: uses birthdate not birth_date in metadata
				// Nationality uses path ["nationalities", null] so we can't check a single string path
			},
		},
		{
			filename:      "vctm_ehic.json",
			expectedLangs: []string{"en-US"},
			expectedLabels: map[string][]string{
				"en-US": {"Social Security PIN", "Issuing authority", "Issuing authority id", "Issuing authority name"},
			},
			samplePathCheck: map[string]string{
				"Social Security PIN":    "personal_administrative_number",
				"Issuing authority id":   "id",
				"Issuing authority name": "name",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.filename, func(t *testing.T) {
			// Load the VCTM file
			filePath := filepath.Join(metadataDir, tc.filename)
			data, err := os.ReadFile(filePath)
			require.NoError(t, err, "Failed to read %s", tc.filename)

			var vctm VCTM
			err = json.Unmarshal(data, &vctm)
			require.NoError(t, err, "Failed to unmarshal %s", tc.filename)

			// Test Attributes()
			attrs := vctm.Attributes()
			assert.NotNil(t, attrs)

			// Check expected languages are present
			for _, lang := range tc.expectedLangs {
				assert.Contains(t, attrs, lang, "Missing language: %s", lang)
			}

			// Check expected labels are present for each language
			for lang, expectedLabels := range tc.expectedLabels {
				require.Contains(t, attrs, lang)
				for _, label := range expectedLabels {
					assert.Contains(t, attrs[lang], label, "Missing label '%s' for language %s", label, lang)
				}
			}

			// Check specific path mappings
			for label, expectedPath := range tc.samplePathCheck {
				for lang := range tc.expectedLabels {
					if paths, ok := attrs[lang][label]; ok {
						assert.NotEmpty(t, paths, "Label '%s' should have paths", label)
						// Check if the expected path is in the paths slice
						found := false
						for _, path := range paths {
							if path == expectedPath {
								found = true
								break
							}
						}
						assert.True(t, found, "Expected path '%s' not found for label '%s'", expectedPath, label)
					}
				}
			}
		})
	}
}

func TestVCTM_Attributes_EmptyClaims(t *testing.T) {
	vctm := &VCTM{
		Claims: []Claim{},
	}

	attrs := vctm.Attributes()
	assert.NotNil(t, attrs)
	assert.Empty(t, attrs)
}

func TestVCTM_ClaimJSONPath(t *testing.T) {
	name := "name"
	given := "given"
	family := "family"

	vctm := &VCTM{
		Claims: []Claim{
			{
				Path:  []*string{&name},
				SVGID: "name-field",
			},
			{
				Path:  []*string{&name, &given},
				SVGID: "given-name",
			},
			{
				Path: []*string{&family},
			},
		},
	}

	jsonPath, err := vctm.ClaimJSONPath()
	assert.NoError(t, err)
	assert.NotNil(t, jsonPath)

	assert.Contains(t, jsonPath.Displayable, "name-field")
	assert.Equal(t, "$.name", jsonPath.Displayable["name-field"])
	assert.Contains(t, jsonPath.Displayable, "given-name")
	assert.Equal(t, "$.name.given", jsonPath.Displayable["given-name"])

	assert.Len(t, jsonPath.AllClaims, 3)
	assert.Contains(t, jsonPath.AllClaims, "$.name")
	assert.Contains(t, jsonPath.AllClaims, "$.name.given")
	assert.Contains(t, jsonPath.AllClaims, "$.family")
}

func TestVCTM_ClaimJSONPath_NilClaims(t *testing.T) {
	vctm := &VCTM{
		Claims: nil,
	}

	jsonPath, err := vctm.ClaimJSONPath()
	assert.Error(t, err)
	assert.Nil(t, jsonPath)
	assert.Contains(t, err.Error(), "claims are nil")
}

func TestClaim_JSONPath(t *testing.T) {
	t.Run("simple_path", func(t *testing.T) {
		name := "name"
		claim := &Claim{
			Path: []*string{&name},
		}

		path := claim.JSONPath()
		assert.Equal(t, "$.name", path)
	})

	t.Run("nested_path", func(t *testing.T) {
		address := "address"
		street := "street"
		claim := &Claim{
			Path: []*string{&address, &street},
		}

		path := claim.JSONPath()
		assert.Equal(t, "$.address.street", path)
	})

	t.Run("nil_claim", func(t *testing.T) {
		var claim *Claim = nil
		path := claim.JSONPath()
		assert.Equal(t, "", path)
	})

	t.Run("nil_path", func(t *testing.T) {
		claim := &Claim{
			Path: nil,
		}

		path := claim.JSONPath()
		assert.Equal(t, "", path)
	})

	t.Run("empty_path", func(t *testing.T) {
		claim := &Claim{
			Path: []*string{},
		}

		path := claim.JSONPath()
		assert.Equal(t, "$", path)
	})

	t.Run("deep_nesting", func(t *testing.T) {
		a := "a"
		b := "b"
		c := "c"
		d := "d"
		claim := &Claim{
			Path: []*string{&a, &b, &c, &d},
		}

		path := claim.JSONPath()
		assert.Equal(t, "$.a.b.c.d", path)
	})
}
