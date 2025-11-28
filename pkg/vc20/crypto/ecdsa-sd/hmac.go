//go:build vc20

package ecdsasd

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// HMACKey represents an HMAC key for blank node label randomization.
// Per ECDSA-SD-2023 spec, the key MUST be 256 bits (32 bytes) when using SHA-256.
type HMACKey []byte

// GenerateHMACKey generates a cryptographically secure random HMAC key.
// Returns a 256-bit (32 byte) key suitable for SHA-256 HMAC operations.
func GenerateHMACKey() (HMACKey, error) {
	key := make([]byte, 32) // 256 bits
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random HMAC key: %w", err)
	}
	return HMACKey(key), nil
}

// NewHMACKey creates an HMAC key from existing bytes.
// The key MUST be exactly 32 bytes (256 bits) for SHA-256.
func NewHMACKey(keyBytes []byte) (HMACKey, error) {
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("HMAC key must be 32 bytes, got %d", len(keyBytes))
	}
	key := make([]byte, 32)
	copy(key, keyBytes)
	return HMACKey(key), nil
}

// Bytes returns the raw bytes of the HMAC key.
func (k HMACKey) Bytes() []byte {
	return []byte(k)
}

// LabelMapKey represents a canonical blank node identifier from RDF
type LabelMapKey string

// CanonicalIdMap maps canonical blank node labels to randomized labels
type CanonicalIdMap map[LabelMapKey]string

// RandomizeBlankNodeLabels creates HMAC-based randomized labels for blank nodes.
// This implements the blank node identifier randomization as specified in
// ECDSA-SD-2023 section on creating base proofs.
//
// For each canonical blank node label:
// 1. Compute HMAC-SHA-256(key, label)
// 2. Encode as hex string
// 3. Prefix with "_:u" to create a valid blank node identifier
//
// Returns a map from canonical labels to randomized labels.
func (k HMACKey) RandomizeBlankNodeLabels(canonicalLabels []string) (CanonicalIdMap, error) {
	if len(k) != 32 {
		return nil, fmt.Errorf("invalid HMAC key length: %d", len(k))
	}

	labelMap := make(CanonicalIdMap, len(canonicalLabels))
	mac := hmac.New(sha256.New, k)

	for _, label := range canonicalLabels {
		// Reset MAC for each label
		mac.Reset()

		// Compute HMAC(key, label)
		mac.Write([]byte(label))
		hmacOutput := mac.Sum(nil)

		// Create randomized label: "_:u" + hex(hmac)
		randomLabel := "_:u" + hex.EncodeToString(hmacOutput)

		labelMap[LabelMapKey(label)] = randomLabel
	}

	return labelMap, nil
}

// ComputeHMAC computes HMAC-SHA-256 of the given data using this key.
// This is a general-purpose HMAC operation used in the cryptosuite.
func (k HMACKey) ComputeHMAC(data []byte) ([]byte, error) {
	if len(k) != 32 {
		return nil, fmt.Errorf("invalid HMAC key length: %d", len(k))
	}

	mac := hmac.New(sha256.New, k)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// VerifyHMAC verifies that the given HMAC matches the expected value for the data.
func (k HMACKey) VerifyHMAC(data []byte, expectedHMAC []byte) (bool, error) {
	if len(k) != 32 {
		return false, fmt.Errorf("invalid HMAC key length: %d", len(k))
	}

	computedHMAC, err := k.ComputeHMAC(data)
	if err != nil {
		return false, err
	}

	return hmac.Equal(computedHMAC, expectedHMAC), nil
}

// ExtractBlankNodeLabels extracts blank node identifiers from N-Quads.
// Blank nodes start with "_:" in RDF N-Quads format.
func ExtractBlankNodeLabels(nquads string) []string {
	var labels []string
	seen := make(map[string]bool)

	// Simple extraction - look for "_:" patterns
	// This is a basic implementation; production code might need more robust parsing
	start := 0
	for {
		idx := indexOf(nquads[start:], "_:")
		if idx == -1 {
			break
		}
		idx += start

		// Extract the label (blank node identifiers are typically alphanumeric after "_:")
		labelStart := idx + 2
		labelEnd := labelStart
		for labelEnd < len(nquads) {
			c := nquads[labelEnd]
			if !isBlankNodeChar(c) {
				break
			}
			labelEnd++
		}

		if labelEnd > labelStart {
			label := nquads[idx:labelEnd]
			if !seen[label] {
				labels = append(labels, label)
				seen[label] = true
			}
		}

		start = labelEnd
	}

	return labels
}

// indexOf returns the index of substr in s, or -1 if not found
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// isBlankNodeChar returns true if the character is valid in a blank node identifier
func isBlankNodeChar(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '_' || c == '-'
}
