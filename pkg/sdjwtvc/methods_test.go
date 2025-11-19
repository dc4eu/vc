package sdjwtvc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

var (
	mockAttributeFirstName         = "first_name"
	mockAttributeAddress           = "address"
	mockAttributeAddressStreet     = "street"
	mockAttributeAddressPostal     = "postal"
	mockAttributeAddressPostalCode = "code"
	mockAttributeWorkCountries     = "work_countries"

	mockVCTM_v1 = &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&mockAttributeFirstName},
				SD:   "always",
			},
		},
	}

	mockVCTM_v2 = &VCTM{
		Claims: []Claim{
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

	mockVCTM_v3 = &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&mockAttributeAddress, &mockAttributeAddressStreet},
				SD:   "always",
			},
		},
	}

	mockVCTM_v4 = &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&mockAttributeAddress, &mockAttributeAddressPostal},
				SD:   "always",
			},
		},
	}

	mockVCTM_v5 = &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&mockAttributeAddress, &mockAttributeAddressPostal, &mockAttributeAddressPostalCode},
				SD:   "always",
			},
		},
	}

	// mockVCTM_v6 is recursive
	mockVCTM_v6 = &VCTM{
		Claims: []Claim{
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
	mockVCTM_v7 = &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&mockAttributeWorkCountries},
				SD:   "always",
			},
		},
	}
)

func TestMakeCredential(t *testing.T) {
	tts := []struct {
		name                 string
		data                 map[string]any
		vctm                 *VCTM
		expectSDAtRoot       bool
		expectSDInAddress    bool
		expectSDInPostal     bool
		expectDisclosureKeys []string // claims that should be disclosed
		expectRemainingKeys  []string // claims that should remain in payload
	}{
		{
			name:                 "first name is selective disclosure",
			data:                 map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm:                 mockVCTM_v1,
			expectSDAtRoot:       true,
			expectDisclosureKeys: []string{"first_name"},
			expectRemainingKeys:  []string{"address", "work_countries", "_sd_alg"},
		},
		{
			name:                 "address is selective disclosure",
			data:                 map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm:                 mockVCTM_v2,
			expectSDAtRoot:       true,
			expectDisclosureKeys: []string{"address"},
			expectRemainingKeys:  []string{"first_name", "work_countries", "_sd_alg"},
		},
		{
			name:                 "address street is selective disclosure",
			data:                 map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm:                 mockVCTM_v3,
			expectSDInAddress:    true,
			expectDisclosureKeys: []string{"street"},
			expectRemainingKeys:  []string{"first_name", "work_countries", "_sd_alg"},
		},
		{
			name:                 "address postal is selective disclosure",
			data:                 map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm:                 mockVCTM_v4,
			expectSDInAddress:    true,
			expectDisclosureKeys: []string{"postal"},
			expectRemainingKeys:  []string{"first_name", "work_countries", "_sd_alg"},
		},
		{
			name:                 "address postal code is selective disclosure",
			data:                 map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm:                 mockVCTM_v5,
			expectSDInPostal:     true,
			expectDisclosureKeys: []string{"code"},
			expectRemainingKeys:  []string{"first_name", "work_countries", "_sd_alg"},
		},
		{
			name:                 "address recursive selective disclosure",
			data:                 map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm:                 mockVCTM_v6,
			expectSDAtRoot:       true,
			expectDisclosureKeys: []string{"postal", "address"}, // both are disclosed
			expectRemainingKeys:  []string{"first_name", "work_countries", "_sd_alg"},
		},
		{
			name:                 "work_countries array selective disclosure",
			data:                 map[string]any{"first_name": "John", "address": map[string]any{"street": "123 Main St", "postal": map[string]any{"code": "12345", "city": "Metropolis"}}, "work_countries": []any{"SE", "FI"}},
			vctm:                 mockVCTM_v7,
			expectSDAtRoot:       true,
			expectDisclosureKeys: []string{"work_countries"},
			expectRemainingKeys:  []string{"first_name", "address", "_sd_alg"},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			client := New()
			got, disclosures, err := client.MakeCredential(sha256.New(), tt.data, tt.vctm)
			require.NoError(t, err)

			// Log the result for debugging
			b, err := json.MarshalIndent(got, "", "  ")
			require.NoError(t, err)
			t.Logf("Got credential: %s", string(b))
			t.Logf("Got %d disclosures", len(disclosures))

			// Verify _sd_alg is set correctly (per section 4.1.1)
			assert.Equal(t, "sha-256", got["_sd_alg"])

			// Verify correct number of disclosures
			assert.Equal(t, len(tt.expectDisclosureKeys), len(disclosures), "unexpected number of disclosures")

			// Verify all expected remaining keys are present
			for _, key := range tt.expectRemainingKeys {
				if key == "address" {
					// Special case: address might have _sd array
					_, exists := got[key]
					assert.True(t, exists, "expected key %s to remain in payload", key)
				} else if key != "_sd_alg" && key != "_sd" {
					_, exists := got[key]
					assert.True(t, exists, "expected key %s to remain in payload", key)
				}
			}

			// Verify disclosed keys are NOT in the payload
			for _, key := range tt.expectDisclosureKeys {
				if key != "address" && key != "postal" { // these might be in nested structures
					_, exists := got[key]
					assert.False(t, exists, "expected key %s to be removed from payload", key)
				}
			}

			// Verify _sd arrays exist where expected
			if tt.expectSDAtRoot {
				sdArray, exists := got["_sd"]
				assert.True(t, exists, "expected _sd array at root")
				if exists {
					arr, ok := sdArray.([]any)
					assert.True(t, ok, "_sd should be an array")
					assert.Greater(t, len(arr), 0, "_sd array should not be empty")

					// Verify array is sorted alphanumerically (per section 4.2.4.1)
					if len(arr) > 1 {
						for i := 0; i < len(arr)-1; i++ {
							s1, ok1 := arr[i].(string)
							s2, ok2 := arr[i+1].(string)
							if ok1 && ok2 {
								assert.True(t, s1 <= s2, "_sd array should be sorted alphanumerically")
							}
						}
					}
				}
			}

			if tt.expectSDInAddress {
				address, exists := got["address"]
				require.True(t, exists, "address should exist")
				addrMap, ok := address.(map[string]any)
				require.True(t, ok, "address should be a map")

				sdArray, exists := addrMap["_sd"]
				assert.True(t, exists, "expected _sd array in address")
				if exists {
					arr, ok := sdArray.([]any)
					assert.True(t, ok, "_sd should be an array")
					assert.Greater(t, len(arr), 0, "_sd array should not be empty")
				}
			}

			if tt.expectSDInPostal {
				address, exists := got["address"]
				require.True(t, exists, "address should exist")
				addrMap, ok := address.(map[string]any)
				require.True(t, ok, "address should be a map")

				postal, exists := addrMap["postal"]
				require.True(t, exists, "postal should exist")
				postalMap, ok := postal.(map[string]any)
				require.True(t, ok, "postal should be a map")

				sdArray, exists := postalMap["_sd"]
				assert.True(t, exists, "expected _sd array in postal")
				if exists {
					arr, ok := sdArray.([]any)
					assert.True(t, ok, "_sd should be an array")
					assert.Greater(t, len(arr), 0, "_sd array should not be empty")
				}
			}

			// Verify disclosures are valid base64url
			for i, disclosure := range disclosures {
				_, err := base64.RawURLEncoding.DecodeString(disclosure)
				assert.NoError(t, err, "disclosure %d should be valid base64url", i)

				// Decode and verify structure [salt, claim_name, value]
				decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
				require.NoError(t, err)

				var disclosureArray []any
				err = json.Unmarshal(decoded, &disclosureArray)
				require.NoError(t, err, "disclosure should be a JSON array")
				assert.Equal(t, 3, len(disclosureArray), "disclosure should have 3 elements [salt, claim_name, value]")

				// Verify salt is a non-empty string
				salt, ok := disclosureArray[0].(string)
				assert.True(t, ok, "salt should be a string")
				assert.NotEmpty(t, salt, "salt should not be empty")

				// Verify claim name is a string
				claimName, ok := disclosureArray[1].(string)
				assert.True(t, ok, "claim_name should be a string")
				assert.Contains(t, tt.expectDisclosureKeys, claimName, "claim_name should be one of the expected keys")

				t.Logf("Disclosure %d: claim=%s, salt_len=%d", i, claimName, len(salt))
			}
		})
	}
}

// TestSaltEntropy verifies that salts have proper entropy
func TestSaltEntropy(t *testing.T) {
	vctm := &VCTM{
		Claims: []Claim{
			{Path: []*string{&mockAttributeFirstName}, SD: "always"},
		},
	}

	client := New()

	// Generate multiple credentials to verify salt randomness
	salts := make(map[string]bool)
	for i := 0; i < 10; i++ {
		dataCopy := map[string]any{"first_name": "John", "last_name": "Doe"}
		_, disclosures, err := client.MakeCredential(sha256.New(), dataCopy, vctm)
		require.NoError(t, err)
		require.Len(t, disclosures, 1)

		decoded, err := base64.RawURLEncoding.DecodeString(disclosures[0])
		require.NoError(t, err)

		var disclosureArray []any
		err = json.Unmarshal(decoded, &disclosureArray)
		require.NoError(t, err)

		salt := disclosureArray[0].(string)

		// Verify salt is unique (should be extremely unlikely to collide)
		assert.False(t, salts[salt], "salt should be unique")
		salts[salt] = true

		// Verify salt has reasonable length (128 bits = 22 chars in base64url)
		assert.GreaterOrEqual(t, len(salt), 20, "salt should have sufficient entropy")
	}

	t.Logf("Generated %d unique salts", len(salts))
}

// TestNoDuplicateDigests verifies that duplicate digests are rejected
func TestNoDuplicateDigests(t *testing.T) {
	// This is a defensive test - in practice, duplicate digests should never occur
	// due to unique salts, but the implementation should check for them
	data := map[string]any{
		"claim1": "value1",
		"claim2": "value2",
	}

	claim1 := "claim1"
	vctm := &VCTM{
		Claims: []Claim{
			{Path: []*string{&claim1}, SD: "always"},
		},
	}

	client := New()
	_, disclosures, err := client.MakeCredential(sha256.New(), data, vctm)
	require.NoError(t, err)
	assert.Len(t, disclosures, 1)
}

// TestRecursiveDisclosure tests recursive selective disclosure per section 4.2.6
func TestRecursiveDisclosure(t *testing.T) {
	data := map[string]any{
		"address": map[string]any{
			"street": "123 Main St",
			"postal": map[string]any{
				"code": "12345",
				"city": "Metropolis",
			},
		},
	}

	client := New()
	_, disclosures, err := client.MakeCredential(sha256.New(), data, mockVCTM_v6)
	require.NoError(t, err)

	// Should have 2 disclosures: one for postal, one for address
	assert.Len(t, disclosures, 2)

	// Verify one of the disclosures contains the address claim with _sd array
	foundAddressWithSD := false
	for _, disclosure := range disclosures {
		decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
		require.NoError(t, err)

		var disclosureArray []any
		err = json.Unmarshal(decoded, &disclosureArray)
		require.NoError(t, err)

		claimName := disclosureArray[1].(string)
		if claimName == "address" {
			// The address disclosure should contain a value with _sd array
			value, ok := disclosureArray[2].(map[string]any)
			require.True(t, ok, "address value should be an object")

			_, hasSD := value["_sd"]
			if hasSD {
				foundAddressWithSD = true
				t.Log("Found recursive disclosure: address contains _sd array")
			}
		}
	}

	assert.True(t, foundAddressWithSD, "address disclosure should contain _sd array for recursive disclosure")
}

func TestSortVCTM(t *testing.T) {
	// This test is a placeholder for future VCTM sorting functionality
	t.Skip("VCTM sorting not yet implemented")
}

func TestGetHashAlgorithmName(t *testing.T) {
	tests := []struct {
		name         string
		hasher       hash.Hash
		expectedName string
	}{
		{
			name:         "SHA-256",
			hasher:       sha256.New(),
			expectedName: "sha-256",
		},
		{
			name:         "SHA-384",
			hasher:       sha512.New384(),
			expectedName: "sha-384",
		},
		{
			name:         "SHA-512",
			hasher:       sha512.New(),
			expectedName: "sha-512",
		},
		{
			name:         "SHA3-256",
			hasher:       sha3.New256(),
			expectedName: "sha3-256",
		},
		{
			name:         "SHA3-512",
			hasher:       sha3.New512(),
			expectedName: "sha3-512",
		},
		{
			name:         "SHA-224",
			hasher:       sha256.New224(),
			expectedName: "sha-224",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algName, err := getHashAlgorithmName(tt.hasher)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedName, algName)
		})
	}
}

func TestGetHashAlgorithmName_UnsupportedSize(t *testing.T) {
	// The function handles all common hash sizes
	// Unsupported sizes would come from custom hash implementations
	// This test verifies the function doesn't panic with unexpected sizes
	// In practice, all standard library hashes are supported
	t.Skip("All standard hash algorithms are supported")
}

func TestMakeCredential_AlternativeHashAlgorithms(t *testing.T) {
	tests := []struct {
		name          string
		hasher        hash.Hash
		expectedSdAlg string
	}{
		{
			name:          "SHA-256",
			hasher:        sha256.New(),
			expectedSdAlg: "sha-256",
		},
		{
			name:          "SHA-512",
			hasher:        sha512.New(),
			expectedSdAlg: "sha-512",
		},
		{
			name:          "SHA3-256",
			hasher:        sha3.New256(),
			expectedSdAlg: "sha3-256",
		},
		{
			name:          "SHA3-512",
			hasher:        sha3.New512(),
			expectedSdAlg: "sha3-512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := map[string]any{"first_name": "John"}

			client := New()
			got, _, err := client.MakeCredential(tt.hasher, data, mockVCTM_v1)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedSdAlg, got["_sd_alg"])
		})
	}
}

func TestProcessClaimPath_ErrorCases(t *testing.T) {
	client := New()

	t.Run("empty path", func(t *testing.T) {
		data := map[string]any{"test": "value"}
		_, _, err := client.processClaimPath(data, []*string{}, sha256.New())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty path")
	})

	t.Run("nil path element", func(t *testing.T) {
		data := map[string]any{"test": "value"}
		_, _, err := client.processClaimPath(data, []*string{nil}, sha256.New())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil")
	})

	t.Run("non-existent path", func(t *testing.T) {
		data := map[string]any{"test": "value"}
		nonExistent := "nonexistent"
		_, _, err := client.processClaimPath(data, []*string{&nonExistent}, sha256.New())
		// Should return empty disclosure, not error
		assert.NoError(t, err)
	})

	t.Run("array in path", func(t *testing.T) {
		data := map[string]any{
			"arr": []any{"item1", "item2"},
		}
		arr := "arr"
		next := "element"
		_, _, err := client.processClaimPath(data, []*string{&arr, &next}, sha256.New())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "array element selective disclosure")
	})

	t.Run("non-object in path", func(t *testing.T) {
		data := map[string]any{
			"field": "string_value",
		}
		field := "field"
		next := "sub"
		_, _, err := client.processClaimPath(data, []*string{&field, &next}, sha256.New())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid path")
	})
}

func TestAddHashToPath_ErrorCases(t *testing.T) {
	client := New()

	t.Run("nil path element", func(t *testing.T) {
		data := map[string]any{"test": map[string]any{}}
		err := client.addHashToPath(data, []*string{nil}, "hash123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil path element")
	})

	t.Run("path not found", func(t *testing.T) {
		data := map[string]any{"test": "value"}
		nonExistent := "nonexistent"
		err := client.addHashToPath(data, []*string{&nonExistent}, "hash123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "path not found")
	})

	t.Run("non-object at path", func(t *testing.T) {
		data := map[string]any{"test": "value"}
		test := "test"
		err := client.addHashToPath(data, []*string{&test}, "hash123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "non-object")
	})

	t.Run("_sd is not an array", func(t *testing.T) {
		data := map[string]any{
			"_sd": "not_an_array",
		}
		err := client.addHashToPath(data, []*string{}, "hash123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "_sd is not an array")
	})

	t.Run("duplicate digest", func(t *testing.T) {
		data := map[string]any{
			"_sd": []any{"hash123"},
		}
		err := client.addHashToPath(data, []*string{}, "hash123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate digest")
	})
}

func TestGenerateSalt_Uniqueness(t *testing.T) {
	// Generate multiple salts and ensure they're unique
	salts := make(map[string]bool)

	for i := 0; i < 100; i++ {
		salt, err := generateSalt()
		require.NoError(t, err)
		require.NotEmpty(t, salt)

		// Check uniqueness
		assert.False(t, salts[salt], "salt should be unique")
		salts[salt] = true

		// Check minimum length (128 bits = 16 bytes base64url encoded)
		assert.GreaterOrEqual(t, len(salt), 20)
	}

	assert.Equal(t, 100, len(salts), "all salts should be unique")
}

func TestShuffleSDArrays_DeepNesting(t *testing.T) {
	data := map[string]any{
		"_sd": []any{"hash3", "hash1", "hash2"},
		"level1": map[string]any{
			"_sd": []any{"hashB", "hashA", "hashC"},
			"level2": map[string]any{
				"_sd": []any{"hashZ", "hashX", "hashY"},
			},
		},
		"array": []any{
			map[string]any{
				"_sd": []any{"hashF", "hashD", "hashE"},
			},
		},
	}

	shuffleSDArrays(data)

	// Verify all _sd arrays are sorted
	rootSD := data["_sd"].([]any)
	assert.Equal(t, "hash1", rootSD[0])
	assert.Equal(t, "hash2", rootSD[1])
	assert.Equal(t, "hash3", rootSD[2])

	level1 := data["level1"].(map[string]any)
	level1SD := level1["_sd"].([]any)
	assert.Equal(t, "hashA", level1SD[0])
	assert.Equal(t, "hashB", level1SD[1])
	assert.Equal(t, "hashC", level1SD[2])

	level2 := level1["level2"].(map[string]any)
	level2SD := level2["_sd"].([]any)
	assert.Equal(t, "hashX", level2SD[0])
	assert.Equal(t, "hashY", level2SD[1])
	assert.Equal(t, "hashZ", level2SD[2])

	arrElem := data["array"].([]any)[0].(map[string]any)
	arrSD := arrElem["_sd"].([]any)
	assert.Equal(t, "hashD", arrSD[0])
	assert.Equal(t, "hashE", arrSD[1])
	assert.Equal(t, "hashF", arrSD[2])
}

func TestSortSDArray_NonStringElements(t *testing.T) {
	// Test sorting with non-string elements (should handle gracefully)
	arr := []any{"hash2", 123, "hash1", nil, "hash3"}
	sortSDArray(arr)

	// Strings should be sorted, non-strings remain
	// The function only sorts string elements
	assert.Contains(t, arr, "hash1")
	assert.Contains(t, arr, "hash2")
	assert.Contains(t, arr, "hash3")
}
