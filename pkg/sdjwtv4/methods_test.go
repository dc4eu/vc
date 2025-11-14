package sdjwtv4

import (
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
				Path: []*string{&mockAttributeAddress, &mockAttributeAddressPostal, &mockAttributeAddressPostalCode},
				SD:   "always",
			},
		},
	}
)

func TestMakeCredential(t *testing.T) {
	tts := []struct {
		name string
		data map[string]any
		vctm *sdjwt3.VCTM
		want map[string]any
	}{
		{
			name: "first name is selective disclosure",
			data: map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm: mockVCTM_v1,
			want: map[string]any{
				"_sd": []any{
					"mockSDJWTHash_first_name",
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
		},
		{
			name: "address is selective disclosure",
			data: map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm: mockVCTM_v2,
			want: map[string]any{
				"_sd": []any{
					"mockSDJWTHash_address",
				},
				"_sd_alg":        "sha256",
				"first_name":     "John",
				"work_countries": []any{"SE", "FI"},
			},
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
						"mockSDJWTHash_street",
					},
					"postal": map[string]any{
						"code": "12345",
						"city": "Metropolis",
					},
				},
			},
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
						"mockSDJWTHash_postal",
					},
				},
			},
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
							"mockSDJWTHash_code",
						},
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			client := New()
			got, err := client.MakeCredential(tt.data, tt.vctm)
			assert.NoError(t, err)

			b, err := json.MarshalIndent(got, "", " ")
			assert.NoError(t, err)
			t.Logf("Got credential: %s", string(b))

			assert.Equal(t, tt.want, got)
		})
	}
}
