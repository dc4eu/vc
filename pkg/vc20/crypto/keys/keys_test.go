//go:build vc20

package keys


import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
)

func TestECDSAPublicKeyToMultikey_P256(t *testing.T) {
	// Generate a P-256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	multikey, err := ECDSAPublicKeyToMultikey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("ECDSAPublicKeyToMultikey() error = %v", err)
	}

	// Should start with 'z' (base58-btc multibase prefix)
	if !strings.HasPrefix(multikey, "z") {
		t.Errorf("multikey should start with 'z', got %s", multikey[:1])
	}

	// Should be reasonably long (base58 encoding of ~67 bytes)
	if len(multikey) < 80 {
		t.Errorf("multikey seems too short: %d characters", len(multikey))
	}
}

func TestECDSAPublicKeyToMultikey_P384(t *testing.T) {
	// Generate a P-384 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	multikey, err := ECDSAPublicKeyToMultikey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("ECDSAPublicKeyToMultikey() error = %v", err)
	}

	// Should start with 'z'
	if !strings.HasPrefix(multikey, "z") {
		t.Errorf("multikey should start with 'z', got %s", multikey[:1])
	}

	// P-384 multikey should be longer than P-256
	if len(multikey) < 120 {
		t.Errorf("P-384 multikey seems too short: %d characters", len(multikey))
	}
}

func TestMultikeyRoundtrip_P256(t *testing.T) {
	// Generate a P-256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	originalPubKey := &privKey.PublicKey

	// Encode to multikey
	multikey, err := ECDSAPublicKeyToMultikey(originalPubKey)
	if err != nil {
		t.Fatalf("ECDSAPublicKeyToMultikey() error = %v", err)
	}

	// Decode back to public key
	decodedPubKey, err := MultikeyToECDSAPublicKey(multikey)
	if err != nil {
		t.Fatalf("MultikeyToECDSAPublicKey() error = %v", err)
	}

	// Compare X and Y coordinates
	if originalPubKey.X.Cmp(decodedPubKey.X) != 0 {
		t.Error("X coordinate mismatch after roundtrip")
	}
	if originalPubKey.Y.Cmp(decodedPubKey.Y) != 0 {
		t.Error("Y coordinate mismatch after roundtrip")
	}

	// Verify curve
	if decodedPubKey.Curve.Params().Name != "P-256" {
		t.Errorf("expected P-256 curve, got %s", decodedPubKey.Curve.Params().Name)
	}
}

func TestMultikeyRoundtrip_P384(t *testing.T) {
	// Generate a P-384 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	originalPubKey := &privKey.PublicKey

	// Encode to multikey
	multikey, err := ECDSAPublicKeyToMultikey(originalPubKey)
	if err != nil {
		t.Fatalf("ECDSAPublicKeyToMultikey() error = %v", err)
	}

	// Decode back to public key
	decodedPubKey, err := MultikeyToECDSAPublicKey(multikey)
	if err != nil {
		t.Fatalf("MultikeyToECDSAPublicKey() error = %v", err)
	}

	// Compare X and Y coordinates
	if originalPubKey.X.Cmp(decodedPubKey.X) != 0 {
		t.Error("X coordinate mismatch after roundtrip")
	}
	if originalPubKey.Y.Cmp(decodedPubKey.Y) != 0 {
		t.Error("Y coordinate mismatch after roundtrip")
	}

	// Verify curve
	if decodedPubKey.Curve.Params().Name != "P-384" {
		t.Errorf("expected P-384 curve, got %s", decodedPubKey.Curve.Params().Name)
	}
}

func TestECDSAPublicKeyToMultikey_InvalidCurve(t *testing.T) {
	// P-521 is not supported by ECDSA-SD-2023
	privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	_, err = ECDSAPublicKeyToMultikey(&privKey.PublicKey)
	if err == nil {
		t.Error("expected error for unsupported P-521 curve")
	}
	if !strings.Contains(err.Error(), "unsupported curve") {
		t.Errorf("expected 'unsupported curve' error, got %v", err)
	}
}

func TestECDSAPublicKeyToMultikey_NilKey(t *testing.T) {
	_, err := ECDSAPublicKeyToMultikey(nil)
	if err == nil {
		t.Error("expected error for nil public key")
	}
}

func TestMultikeyToECDSAPublicKey_EmptyString(t *testing.T) {
	_, err := MultikeyToECDSAPublicKey("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestMultikeyToECDSAPublicKey_InvalidMultibase(t *testing.T) {
	_, err := MultikeyToECDSAPublicKey("invalid-multibase!!!")
	if err == nil {
		t.Error("expected error for invalid multibase")
	}
}

func TestMultikeyToECDSAPublicKey_InvalidMulticodec(t *testing.T) {
	// Create a valid multibase encoding but with wrong multicodec
	invalidMultikey := "zInvalidMulticodec"
	_, err := MultikeyToECDSAPublicKey(invalidMultikey)
	if err == nil {
		t.Error("expected error for invalid multicodec")
	}
}

func TestGetCurveName(t *testing.T) {
	tests := []struct {
		name       string
		curve      elliptic.Curve
		wantName   string
		wantErr    bool
	}{
		{
			name:     "P-256",
			curve:    elliptic.P256(),
			wantName: "P-256",
			wantErr:  false,
		},
		{
			name:     "P-384",
			curve:    elliptic.P384(),
			wantName: "P-384",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			gotName, err := GetCurveName(&privKey.PublicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCurveName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotName != tt.wantName {
				t.Errorf("GetCurveName() = %v, want %v", gotName, tt.wantName)
			}
		})
	}
}

func TestGetCurveName_NilKey(t *testing.T) {
	_, err := GetCurveName(nil)
	if err == nil {
		t.Error("expected error for nil public key")
	}
}
