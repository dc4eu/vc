package openid4vp

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestGenerateCodeVerifier(t *testing.T) {
	const allowedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	const expectedLength = 128
	verifiers := make(map[string]bool)

	for i := 0; i < 100; i++ {
		verifier, err := GenerateCodeVerifier()
		if err != nil {
			t.Fatalf("Error generating code_verifier: %v", err)
		}

		if len(verifier) != expectedLength {
			t.Errorf("Invalid length: got %d, expected %d", len(verifier), expectedLength)
		}

		for _, char := range verifier {
			if !contains(allowedChars, char) {
				t.Errorf("Invalid character in code_verifier: %c", char)
			}
		}

		if verifiers[verifier] {
			t.Errorf("Generated code_verifier is not unique: %s", verifier)
		}
		verifiers[verifier] = true
	}
}

func TestGenerateCodeChallenge(t *testing.T) {
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("Error generating code_verifier: %v", err)
	}

	challenge := GenerateCodeChallenge(verifier)

	if challenge == "" {
		t.Fatal("Generated code_challenge is empty")
	}

	expectedHash := sha256.Sum256([]byte(verifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(expectedHash[:])

	if challenge != expectedChallenge {
		t.Errorf("Incorrect code_challenge:\nGot: %s\nExpected: %s", challenge, expectedChallenge)
	}
}

func contains(s string, c rune) bool {
	for _, char := range s {
		if char == c {
			return true
		}
	}
	return false
}
