package sdjwt3

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

var (
	address       = "address"
	streetAddress = "street_address"
)

func TestVCTMJSONPath(t *testing.T) {
	// Test cases for VCTM claim path
	tts := []struct {
		name  string
		claim Claim
		want  string
	}{
		{
			name: "no level",
			claim: Claim{
				Path:    []*string{},
				Display: []ClaimDisplay{},
			},
			want: "$",
		},
		{
			name: "one level",
			claim: Claim{
				Path:    []*string{&address},
				Display: []ClaimDisplay{},
			},
			want: "$.address",
		},
		{
			name: "two levels",
			claim: Claim{
				Path:    []*string{&address, &streetAddress},
				Display: []ClaimDisplay{},
			},
			want: "$.address.street_address",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {

			got := tt.claim.JSONPath()
			fmt.Println("Claim JSONPath:", got)

			assert.Equal(t, tt.want, got, "JSONPath should match expected value")
		})
	}
}

func TestVCTMClaimJSONPath(t *testing.T) {
	tts := []struct {
		name    string
		vctPath string
		want    *VCTMJSONPath
	}{
		{
			name:    "ehic",
			vctPath: "vctm_ehic.golden",
			want: &VCTMJSONPath{
				Displayable: map[string]string{
					"authentic_source_id_7a":           "$.authentic_source.id",
					"authentic_source_name_7b":         "$.authentic_source.name",
					"date_of_expiry_9":                 "$.date_of_expiry",
					"document_number_8":                "$.document_number",
					"issuing_country_2":                "$.issuing_country",
					"personal_administrative_number_6": "$.personal_administrative_number",
				},
				AllClaims: []string{
					"$.personal_administrative_number",
					"$.issuing_authority",
					"$.issuing_authority.id",
					"$.issuing_authority.name",
					"$.issuing_country",
					"$.date_of_expiry",
					"$.date_of_issuance",
					"$.authentic_source",
					"$.authentic_source.id",
					"$.authentic_source.name",
					"$.ending_date",
					"$.starting_date",
					"$.document_number",
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			vcmtByte := golden.Get(t, tt.vctPath)

			vctm := &VCTM{}
			if err := json.Unmarshal(vcmtByte, &vctm); err != nil {
				assert.NoError(t, err, "Unmarshalling VCTM should not fail")
			}

			got, err := vctm.ClaimJSONPath()
			assert.NoError(t, err, "ClaimJSONPath should not fail")

			assert.Equal(t, tt.want, got, "Displayable claims should match")

		})
	}
}
