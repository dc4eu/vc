package sdjwtv4

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
	"vc/pkg/sdjwt3"

	"github.com/stretchr/testify/assert"
)

var (
	mockAttributeFirstName         = "first_name"
	mockAttributeAddress           = "address"
	mockAttributeAddressStreet     = "street"
	mockAttributeAddressPostal     = "postal"
	mockAttributeAddressPostalCode = "code"
	mockAttributeWorkCountries     = "work_countries"
	mockAttributeWorkCountriesSE   = "SE"

	mockVCTM_v1 = &sdjwt3.VCTM{
		Claims: []sdjwt3.Claim{
			{
				Path: []*string{&mockAttributeFirstName},
				SD:   "always",
			},
		},
	}

	mockVCTM_v2 = &sdjwt3.VCTM{
		Claims: []sdjwt3.Claim{
			{
				Path: []*string{&mockAttributeAddress},
				SD:   "always",
			},
			{
				Path: []*string{&mockAttributeFirstName},
				SD:   "never",
			},
		},
	}

	mockVCTM_v3 = &sdjwt3.VCTM{
		Claims: []sdjwt3.Claim{
			{
				Path: []*string{&mockAttributeAddress, &mockAttributeAddressStreet},
				SD:   "always",
			},
		},
	}

	mockVCTM_v4 = &sdjwt3.VCTM{
		Claims: []sdjwt3.Claim{
			{
				Path: []*string{&mockAttributeAddress, &mockAttributeAddressPostal},
				SD:   "always",
			},
		},
	}

	mockVCTM_v5 = &sdjwt3.VCTM{
		Claims: []sdjwt3.Claim{
			{
				Path: []*string{&mockAttributeAddress, &mockAttributeAddressPostal, &mockAttributeAddressPostalCode},
				SD:   "always",
			},
		},
	}

	// mockVCTM_v6 is recursive
	mockVCTM_v6 = &sdjwt3.VCTM{
		Claims: []sdjwt3.Claim{
			{
				Path: []*string{&mockAttributeAddress, &mockAttributeAddressPostal},
				SD:   "always",
			},
			{
				Path: []*string{&mockAttributeAddress},
				SD:   "always",
			},
		},
	}

	// mockVCTM_v7 tests array handling
	mockVCTM_v7 = &sdjwt3.VCTM{
		Claims: []sdjwt3.Claim{
			{
				Path: []*string{&mockAttributeWorkCountries},
				SD:   "always",
			},
		},
	}

	// mockVCTM_v8 tests value in array
	mockVCTM_v8 = &sdjwt3.VCTM{
		Claims: []sdjwt3.Claim{
			{
				Path: []*string{&mockAttributeWorkCountriesSE},
				SD:   "always",
			},
		},
	}
)

func TestMakeCredential(t *testing.T) {
	tts := []struct {
		name            string
		data            map[string]any
		vctm            *sdjwt3.VCTM
		want            map[string]any
		wantDisclosures []string
	}{
		{
			name: "first name is selective disclosure",
			data: map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm: mockVCTM_v1,
			want: map[string]any{
				"_sd": []any{
					"HGq_Ipq3o3P2negVlLBXN4WS1xCSkV7orgswrvZQT_E",
				},
				"_sd_alg": "sha256",
				"address": map[string]any{
					"street": "123 Main St",
					"postal": map[string]any{
						"code": "12345",
						"city": "Metropolis",
					},
				},
				"work_countries": []any{"SE", "FI"},
			},
			wantDisclosures: []string{"WyJtb2NrU2FsdCIsImZpcnN0X25hbWUiLCJKb2huIl0"},
		},
		{
			name: "address is selective disclosure",
			data: map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm: mockVCTM_v2,
			want: map[string]any{
				"_sd": []any{
					"bKOYxts_vyhjxiuUlTOLhJ2SqHa0h7Eu58gYT9JB0_4",
				},
				"_sd_alg":        "sha256",
				"first_name":     "John",
				"work_countries": []any{"SE", "FI"},
			},
			wantDisclosures: []string{"WyJtb2NrU2FsdCIsImFkZHJlc3MiLHsicG9zdGFsIjp7ImNpdHkiOiJNZXRyb3BvbGlzIiwiY29kZSI6IjEyMzQ1In0sInN0cmVldCI6IjEyMyBNYWluIFN0In1d"},
		},
		{
			name: "address street is selective disclosure",
			data: map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm: mockVCTM_v3,
			want: map[string]any{
				"_sd_alg":        "sha256",
				"first_name":     "John",
				"work_countries": []any{"SE", "FI"},
				"address": map[string]any{
					"_sd": []any{
						"rmNI5ol0ExnIJNNcbB17uXVvyj7YILqR9YtTDMy4G8I",
					},
					"postal": map[string]any{
						"code": "12345",
						"city": "Metropolis",
					},
				},
			},
			wantDisclosures: []string{"WyJtb2NrU2FsdCIsInN0cmVldCIsIjEyMyBNYWluIFN0Il0"},
		},
		{
			name: "address postal is selective disclosure",
			data: map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm: mockVCTM_v4,
			want: map[string]any{
				"_sd_alg":        "sha256",
				"first_name":     "John",
				"work_countries": []any{"SE", "FI"},
				"address": map[string]any{
					"street": "123 Main St",
					"_sd": []any{
						"kicL94PO6ePdEcOz-hsedVfRfJGRBL7nyBLdyDh7gqQ",
					},
				},
			},
			wantDisclosures: []string{"WyJtb2NrU2FsdCIsInBvc3RhbCIseyJjaXR5IjoiTWV0cm9wb2xpcyIsImNvZGUiOiIxMjM0NSJ9XQ"},
		},
		{
			name: "address postal code is selective disclosure",
			data: map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm: mockVCTM_v5,
			want: map[string]any{
				"_sd_alg":        "sha256",
				"first_name":     "John",
				"work_countries": []any{"SE", "FI"},
				"address": map[string]any{
					"street": "123 Main St",
					"postal": map[string]any{
						"city": "Metropolis",
						"_sd": []any{
							"0Rsm-laJQrMzNN1p_p-VUOtykvRYp5YJn_5BitywTi4",
						},
					},
				},
			},
			wantDisclosures: []string{"WyJtb2NrU2FsdCIsImNvZGUiLCIxMjM0NSJd"},
		},
		{
			name: "address recursive selective disclosure",
			data: map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm: mockVCTM_v6,
			want: map[string]any{
				"_sd": []any{
					"7Y-IVH3cWk6FA768awe6xWIhe1MYxuiPGBJaCuSMqRU",
				},
				"_sd_alg":        "sha256",
				"first_name":     "John",
				"work_countries": []any{"SE", "FI"},
			},
			wantDisclosures: []string{"WyJtb2NrU2FsdCIsInBvc3RhbCIseyJjaXR5IjoiTWV0cm9wb2xpcyIsImNvZGUiOiIxMjM0NSJ9XQ", "WyJtb2NrU2FsdCIsImFkZHJlc3MiLHsiX3NkIjpbImtpY0w5NFBPNmVQZEVjT3otaHNlZFZmUmZKR1JCTDdueUJMZHlEaDdncVEiXSwic3RyZWV0IjoiMTIzIE1haW4gU3QifV0"},
		},
		{
			name: "work_countries array selective disclosure",
			data: map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm: mockVCTM_v7,
			want: map[string]any{
				"_sd": []any{
					"6BAP5EILZUnPW0JgFT8Lh8GLQS6_ByjJLvAGmoHqmzI",
				},
				"_sd_alg":    "sha256",
				"first_name": "John",
				"address": map[string]any{
					"street": "123 Main St",
					"postal": map[string]any{
						"code": "12345",
						"city": "Metropolis",
					},
				},
			},
			wantDisclosures: []string{"WyJtb2NrU2FsdCIsIndvcmtfY291bnRyaWVzIixbIlNFIiwiRkkiXV0"},
		},
		//{
		//	name: "SE in work_countries array selective disclosure",
		//	data: map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
		//	vctm: mockVCTM_v8,
		//	want: map[string]any{
		//		"_sd": []any{
		//			"6BAP5EILZUnPW0JgFT8Lh8GLQS6_ByjJLvAGmoHqmzI",
		//		},
		//		"_sd_alg":    "sha256",
		//		"first_name": "John",
		//		"address": map[string]any{
		//			"street": "123 Main St",
		//			"postal": map[string]any{
		//				"code": "12345",
		//				"city": "Metropolis",
		//			},
		//		},
		//		"work_countries": []any{
		//			map[string]any{"...": "asdasd"},
		//			"FI",
		//		},
		//	},
		//	wantDisclosures: []string{"WyJtb2NrU2FsdCIsIndvcmtfY291bnRyaWVzIixbIlNFIiwiRkkiXV0"},
		//},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			client := New()
			got, disclosures, err := client.MakeCredential(sha256.New(), tt.data, tt.vctm)
			assert.NoError(t, err)

			assert.Equal(t, tt.wantDisclosures, disclosures)

			b, err := json.MarshalIndent(got, "", " ")
			assert.NoError(t, err)
			t.Logf("Got credential: %s", string(b))

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSortVCTM(t *testing.T) {
	tts := []struct {
		name string
		vctm *sdjwt3.VCTM
		want []*sdjwt3.Claim
	}{
		{
			name: "sort VCTM claims by path length",
			vctm: &sdjwt3.VCTM{
				Claims: []sdjwt3.Claim{},
			},
			want: []*sdjwt3.Claim{},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			//	got := sdjwt3.SortVCTMClaims(tt.vctm)
			//	assert.Equal(t, tt.want, got)
		})
	}
}
