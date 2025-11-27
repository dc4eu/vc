//go:build vc20

package ecdsasd

import (
	"encoding/hex"
	"testing"
)

func TestGenerateHMACKey(t *testing.T) {
	key, err := GenerateHMACKey()
	if err != nil {
		t.Fatalf("GenerateHMACKey() error = %v", err)
	}

	if len(key) != 32 {
		t.Errorf("GenerateHMACKey() returned key of length %d, expected 32", len(key))
	}

	// Generate another key to ensure randomness
	key2, err := GenerateHMACKey()
	if err != nil {
		t.Fatalf("GenerateHMACKey() error = %v", err)
	}

	// Keys should be different (statistically almost certain)
	if hex.EncodeToString(key) == hex.EncodeToString(key2) {
		t.Error("Two consecutive GenerateHMACKey() calls returned identical keys")
	}
}

func TestNewHMACKey(t *testing.T) {
	validBytes := make([]byte, 32)
	for i := range validBytes {
		validBytes[i] = byte(i)
	}

	key, err := NewHMACKey(validBytes)
	if err != nil {
		t.Fatalf("NewHMACKey() error = %v", err)
	}

	if len(key) != 32 {
		t.Errorf("NewHMACKey() returned key of length %d, expected 32", len(key))
	}

	// Verify bytes match
	if hex.EncodeToString(key.Bytes()) != hex.EncodeToString(validBytes) {
		t.Error("NewHMACKey() key bytes don't match input")
	}
}

func TestNewHMACKey_InvalidLength(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"too short", 16},
		{"too long", 64},
		{"empty", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalidBytes := make([]byte, tt.length)
			_, err := NewHMACKey(invalidBytes)
			if err == nil {
				t.Errorf("NewHMACKey() with %d bytes should return error", tt.length)
			}
		})
	}
}

func TestHMACKey_RandomizeBlankNodeLabels(t *testing.T) {
	key, err := GenerateHMACKey()
	if err != nil {
		t.Fatalf("GenerateHMACKey() error = %v", err)
	}

	labels := []string{"_:c14n0", "_:c14n1", "_:c14n2"}
	labelMap, err := key.RandomizeBlankNodeLabels(labels)
	if err != nil {
		t.Fatalf("RandomizeBlankNodeLabels() error = %v", err)
	}

	// Check that all labels were mapped
	if len(labelMap) != len(labels) {
		t.Errorf("RandomizeBlankNodeLabels() returned %d mappings, expected %d", len(labelMap), len(labels))
	}

	// Check that randomized labels have correct format
	for originalLabel, randomLabel := range labelMap {
		if len(randomLabel) != 67 { // "_:u" + 64 hex chars (32 bytes * 2)
			t.Errorf("Randomized label %s has length %d, expected 67", randomLabel, len(randomLabel))
		}
		if randomLabel[:3] != "_:u" {
			t.Errorf("Randomized label %s doesn't start with '_:u'", randomLabel)
		}

		// Verify determinism - same input should give same output
		labelMap2, err := key.RandomizeBlankNodeLabels([]string{string(originalLabel)})
		if err != nil {
			t.Fatalf("RandomizeBlankNodeLabels() error = %v", err)
		}
		if labelMap2[originalLabel] != randomLabel {
			t.Error("RandomizeBlankNodeLabels() is not deterministic")
		}
	}

	// Check that different labels produce different randomized labels
	seenRandomLabels := make(map[string]bool)
	for _, randomLabel := range labelMap {
		if seenRandomLabels[randomLabel] {
			t.Errorf("Duplicate randomized label: %s", randomLabel)
		}
		seenRandomLabels[randomLabel] = true
	}
}

func TestHMACKey_ComputeHMAC(t *testing.T) {
	// Use a known key for deterministic testing
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i)
	}
	key, err := NewHMACKey(keyBytes)
	if err != nil {
		t.Fatalf("NewHMACKey() error = %v", err)
	}

	data := []byte("test data")
	hmacResult, err := key.ComputeHMAC(data)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	// HMAC-SHA256 output should be 32 bytes
	if len(hmacResult) != 32 {
		t.Errorf("ComputeHMAC() returned %d bytes, expected 32", len(hmacResult))
	}

	// Verify determinism
	hmacResult2, err := key.ComputeHMAC(data)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}
	if hex.EncodeToString(hmacResult) != hex.EncodeToString(hmacResult2) {
		t.Error("ComputeHMAC() is not deterministic")
	}

	// Different data should produce different HMAC
	differentData := []byte("different test data")
	hmacResult3, err := key.ComputeHMAC(differentData)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}
	if hex.EncodeToString(hmacResult) == hex.EncodeToString(hmacResult3) {
		t.Error("ComputeHMAC() produced same result for different data")
	}
}

func TestHMACKey_VerifyHMAC(t *testing.T) {
	key, err := GenerateHMACKey()
	if err != nil {
		t.Fatalf("GenerateHMACKey() error = %v", err)
	}

	data := []byte("test data")
	hmacResult, err := key.ComputeHMAC(data)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	// Verify correct HMAC
	valid, err := key.VerifyHMAC(data, hmacResult)
	if err != nil {
		t.Fatalf("VerifyHMAC() error = %v", err)
	}
	if !valid {
		t.Error("VerifyHMAC() returned false for valid HMAC")
	}

	// Verify incorrect HMAC
	invalidHMAC := make([]byte, 32)
	valid, err = key.VerifyHMAC(data, invalidHMAC)
	if err != nil {
		t.Fatalf("VerifyHMAC() error = %v", err)
	}
	if valid {
		t.Error("VerifyHMAC() returned true for invalid HMAC")
	}
}

func TestExtractBlankNodeLabels(t *testing.T) {
	tests := []struct {
		name     string
		nquads   string
		expected int
	}{
		{
			name:     "no blank nodes",
			nquads:   "<http://example.org/s> <http://example.org/p> \"value\" .\n",
			expected: 0,
		},
		{
			name:     "single blank node",
			nquads:   "_:c14n0 <http://example.org/p> \"value\" .\n",
			expected: 1,
		},
		{
			name: "multiple blank nodes",
			nquads: `_:c14n0 <http://example.org/p> "value" .
_:c14n1 <http://example.org/p> _:c14n2 .
`,
			expected: 3,
		},
		{
			name: "duplicate blank nodes",
			nquads: `_:c14n0 <http://example.org/p> "value" .
_:c14n0 <http://example.org/p2> "value2" .
`,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels := ExtractBlankNodeLabels(tt.nquads)
			if len(labels) != tt.expected {
				t.Errorf("ExtractBlankNodeLabels() returned %d labels, expected %d", len(labels), tt.expected)
				t.Logf("Labels: %v", labels)
			}

			// Verify all extracted labels start with "_:"
			for _, label := range labels {
				if len(label) < 3 || label[:2] != "_:" {
					t.Errorf("ExtractBlankNodeLabels() returned invalid label: %s", label)
				}
			}
		})
	}
}
