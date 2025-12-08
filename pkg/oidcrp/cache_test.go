//go:build oidcrp

package oidcrp

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveCachedCredentials(t *testing.T) {
	// Create temporary directory for test
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "credentials.json")

	// Create registration response
	regResp := &RegistrationResponse{
		ClientID:                "test-client-id",
		ClientSecret:            "test-client-secret",
		RegistrationAccessToken: "test-access-token",
		RegistrationClientURI:   "https://provider.com/clients/test-client-id",
		ClientSecretExpiresAt:   1735689600,
	}

	// Save credentials
	err := saveCachedCredentials(storagePath, regResp)
	if err != nil {
		t.Fatalf("Failed to save credentials: %v", err)
	}

	// Check file exists
	if _, err := os.Stat(storagePath); os.IsNotExist(err) {
		t.Fatal("Credential file was not created")
	}

	// Check file permissions
	info, err := os.Stat(storagePath)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}

	// Should be 0600 (owner read/write only)
	expectedPerms := os.FileMode(0600)
	if info.Mode().Perm() != expectedPerms {
		t.Errorf("Expected file permissions %v, got %v", expectedPerms, info.Mode().Perm())
	}
}

func TestLoadCachedCredentials(t *testing.T) {
	// Create temporary directory for test
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "credentials.json")

	// Create registration response
	regResp := &RegistrationResponse{
		ClientID:                "test-client-id",
		ClientSecret:            "test-client-secret",
		RegistrationAccessToken: "test-access-token",
		RegistrationClientURI:   "https://provider.com/clients/test-client-id",
		ClientSecretExpiresAt:   0, // No expiration
	}

	// Save credentials
	err := saveCachedCredentials(storagePath, regResp)
	if err != nil {
		t.Fatalf("Failed to save credentials: %v", err)
	}

	// Load credentials
	creds, err := loadCachedCredentials(storagePath)
	if err != nil {
		t.Fatalf("Failed to load credentials: %v", err)
	}

	// Verify loaded credentials
	if creds.ClientID != "test-client-id" {
		t.Errorf("Expected client_id 'test-client-id', got %s", creds.ClientID)
	}

	if creds.ClientSecret != "test-client-secret" {
		t.Errorf("Expected client_secret 'test-client-secret', got %s", creds.ClientSecret)
	}

	if creds.RegistrationAccessToken != "test-access-token" {
		t.Errorf("Expected registration_access_token 'test-access-token', got %s", creds.RegistrationAccessToken)
	}

	if creds.RegistrationClientURI != "https://provider.com/clients/test-client-id" {
		t.Errorf("Expected registration_client_uri 'https://provider.com/clients/test-client-id', got %s", creds.RegistrationClientURI)
	}

	// Check that CachedAt was set
	if creds.CachedAt.IsZero() {
		t.Error("Expected CachedAt to be set, got zero time")
	}
}

func TestLoadCachedCredentials_NotFound(t *testing.T) {
	// Try to load from non-existent path
	storagePath := "/tmp/nonexistent-credentials-file.json"

	_, err := loadCachedCredentials(storagePath)
	if err == nil {
		t.Fatal("Expected error when loading non-existent file, got nil")
	}
}

func TestLoadCachedCredentials_Expired(t *testing.T) {
	// Create temporary directory for test
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "credentials.json")

	// Create registration response with expired secret
	expiresAt := time.Now().Add(-1 * time.Hour).Unix() // Expired 1 hour ago
	regResp := &RegistrationResponse{
		ClientID:              "test-client-id",
		ClientSecret:          "test-client-secret",
		ClientSecretExpiresAt: expiresAt,
	}

	// Save credentials
	err := saveCachedCredentials(storagePath, regResp)
	if err != nil {
		t.Fatalf("Failed to save credentials: %v", err)
	}

	// Try to load expired credentials
	_, err = loadCachedCredentials(storagePath)
	if err == nil {
		t.Fatal("Expected error when loading expired credentials, got nil")
	}

	// Check error message mentions expiration
	if err.Error() == "" {
		t.Error("Expected non-empty error message for expired credentials")
	}
}

func TestLoadCachedCredentials_NoExpiration(t *testing.T) {
	// Create temporary directory for test
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "credentials.json")

	// Create registration response with no expiration (0 = never expires)
	regResp := &RegistrationResponse{
		ClientID:              "test-client-id",
		ClientSecret:          "test-client-secret",
		ClientSecretExpiresAt: 0,
	}

	// Save credentials
	err := saveCachedCredentials(storagePath, regResp)
	if err != nil {
		t.Fatalf("Failed to save credentials: %v", err)
	}

	// Load credentials (should succeed)
	creds, err := loadCachedCredentials(storagePath)
	if err != nil {
		t.Fatalf("Failed to load non-expiring credentials: %v", err)
	}

	if creds.ClientID != "test-client-id" {
		t.Errorf("Expected client_id 'test-client-id', got %s", creds.ClientID)
	}
}

func TestLoadCachedCredentials_FutureExpiration(t *testing.T) {
	// Create temporary directory for test
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "credentials.json")

	// Create registration response with future expiration
	expiresAt := time.Now().Add(24 * time.Hour).Unix() // Expires in 24 hours
	regResp := &RegistrationResponse{
		ClientID:              "test-client-id",
		ClientSecret:          "test-client-secret",
		ClientSecretExpiresAt: expiresAt,
	}

	// Save credentials
	err := saveCachedCredentials(storagePath, regResp)
	if err != nil {
		t.Fatalf("Failed to save credentials: %v", err)
	}

	// Load credentials (should succeed)
	creds, err := loadCachedCredentials(storagePath)
	if err != nil {
		t.Fatalf("Failed to load future-expiring credentials: %v", err)
	}

	if creds.ClientID != "test-client-id" {
		t.Errorf("Expected client_id 'test-client-id', got %s", creds.ClientID)
	}
}

func TestSaveCachedCredentials_EmptyPath(t *testing.T) {
	// Create registration response
	regResp := &RegistrationResponse{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	// Try to save with empty path (should not error, just skip)
	err := saveCachedCredentials("", regResp)
	if err != nil {
		t.Errorf("Expected nil error for empty storage path, got %v", err)
	}
}

func TestLoadCachedCredentials_EmptyPath(t *testing.T) {
	// Try to load with empty path
	_, err := loadCachedCredentials("")
	if err == nil {
		t.Fatal("Expected error when loading with empty path, got nil")
	}
}
