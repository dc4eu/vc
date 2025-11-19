package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestToken_Parse_WithRealCredential(t *testing.T) {
	// Create a real SD-JWT credential for testing
	client := New()

	// Generate keys
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	holderJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "base64url...",
		"y":   "base64url...",
		"kid": "holder-key-1",
	}

	vctm := &VCTM{
		VCT:  "https://example.com/credentials/test",
		Name: "Test Credential",
	}

	documentData := []byte(`{
		"given_name": "John",
		"family_name": "Doe",
		"birthdate": "1990-01-01"
	}`)

	// Build credential
	token, err := client.BuildCredential(
		"https://issuer.example.com",
		"issuer-key-1",
		privateKey,
		"TestCredential",
		documentData,
		holderJWK,
		vctm,
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to build credential: %v", err)
	}

	// Now parse it using Token.Parse()
	parsed, err := Token(token).Parse()
	if err != nil {
		t.Fatalf("Token.Parse() error = %v", err)
	}

	// Verify parsed structure
	if parsed == nil {
		t.Fatal("Token.Parse() returned nil ParsedCredential")
	}

	// Check claims
	if parsed.Claims == nil {
		t.Fatal("Claims is nil")
	}

	// Verify issuer
	if iss, ok := parsed.Claims["iss"].(string); !ok || iss != "https://issuer.example.com" {
		t.Errorf("Expected iss = https://issuer.example.com, got %v", parsed.Claims["iss"])
	}

	// Verify VCT
	if vct, ok := parsed.Claims["vct"].(string); !ok || vct != "TestCredential" {
		t.Errorf("Expected vct = TestCredential, got %v", parsed.Claims["vct"])
	}

	// Verify disclosed claims are present
	if _, ok := parsed.Claims["given_name"]; !ok {
		t.Error("Expected given_name to be disclosed in claims")
	}
	if _, ok := parsed.Claims["family_name"]; !ok {
		t.Error("Expected family_name to be disclosed in claims")
	}
	if _, ok := parsed.Claims["birthdate"]; !ok {
		t.Error("Expected birthdate to be disclosed in claims")
	}

	// Verify disclosures array (may be 0 if all claims are in the JWT body)
	t.Logf("Number of selective disclosures: %d", len(parsed.Disclosures))

	// Verify header
	if parsed.Header == nil {
		t.Fatal("Header is nil")
	}

	if alg, ok := parsed.Header["alg"].(string); !ok || alg != "ES256" {
		t.Errorf("Expected alg = ES256, got %v", parsed.Header["alg"])
	}

	// Verify internal claims are removed
	if _, ok := parsed.Claims["_sd"]; ok {
		t.Error("Expected _sd to be removed from final claims")
	}
	if _, ok := parsed.Claims["_sd_alg"]; ok {
		t.Error("Expected _sd_alg to be removed from final claims")
	}

	// Verify signature is present
	if parsed.Signature == "" {
		t.Error("Expected signature to be present")
	}

	t.Logf("Successfully parsed credential with %d disclosures", len(parsed.Disclosures))
	t.Logf("Claims: %v", parsed.Claims)
}

func TestToken_Parse(t *testing.T) {
	tests := []struct {
		name              string
		token             string
		wantErr           bool
		expectedClaims    map[string]string // simplified for testing
		expectedDiscCount int
	}{
		{
			name: "valid SD-JWT with disclosures",
			// This is a sample token - in real usage, this would be a valid SD-JWT
			token:             "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCJ9.eyJfc2QiOlsiaGFzaDEiLCJoYXNoMiJdLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwidmN0IjoidXJuOmV4YW1wbGU6cGlkIn0.c2lnbmF0dXJl~disclosure1~disclosure2~",
			wantErr:           false,
			expectedDiscCount: 2,
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
		},
		{
			name:    "invalid base64 header",
			token:   "invalid~~~",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := Token(tt.token).Parse()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Token.Parse() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Token.Parse() unexpected error = %v", err)
				return
			}

			if parsed == nil {
				t.Error("Token.Parse() returned nil ParsedCredential")
				return
			}

			if len(parsed.Disclosures) != tt.expectedDiscCount {
				t.Errorf("Token.Parse() got %d disclosures, want %d", len(parsed.Disclosures), tt.expectedDiscCount)
			}

			if parsed.Claims == nil {
				t.Error("Token.Parse() Claims is nil")
			}

			if parsed.Header == nil {
				t.Error("Token.Parse() Header is nil")
			}
		})
	}
}

func TestToken_Split(t *testing.T) {
	tests := []struct {
		name                  string
		token                 string
		wantErr               bool
		expectedDisclosures   int
		expectedKeyBindingLen int
	}{
		{
			name:                  "token with disclosures and key binding",
			token:                 "header.payload.signature~disc1~disc2~kb.header.payload.signature",
			wantErr:               false,
			expectedDisclosures:   2,
			expectedKeyBindingLen: 4,
		},
		{
			name:                  "token with disclosures no key binding",
			token:                 "header.payload.signature~disc1~",
			wantErr:               false,
			expectedDisclosures:   1,
			expectedKeyBindingLen: 0,
		},
		{
			name:                "empty token",
			token:               "",
			wantErr:             true,
			expectedDisclosures: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, body, sig, disclosures, keyBinding, err := Token(tt.token).Split()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Token.Split() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Token.Split() unexpected error = %v", err)
				return
			}

			if header == "" || body == "" || sig == "" {
				t.Error("Token.Split() header, body, or signature is empty")
			}

			if len(disclosures) != tt.expectedDisclosures {
				t.Errorf("Token.Split() got %d disclosures, want %d", len(disclosures), tt.expectedDisclosures)
			}

			if len(keyBinding) != tt.expectedKeyBindingLen {
				t.Errorf("Token.Split() got %d key binding parts, want %d", len(keyBinding), tt.expectedKeyBindingLen)
			}
		})
	}
}
