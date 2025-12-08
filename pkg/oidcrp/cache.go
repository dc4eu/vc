//go:build oidcrp

package oidcrp

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// CachedCredentials represents dynamically registered client credentials stored on disk
type CachedCredentials struct {
	ClientID                string    `json:"client_id"`
	ClientSecret            string    `json:"client_secret"`
	RegistrationAccessToken string    `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string    `json:"registration_client_uri,omitempty"`
	ClientSecretExpiresAt   int64     `json:"client_secret_expires_at,omitempty"`
	CachedAt                time.Time `json:"cached_at"`
}

// loadCachedCredentials loads dynamically registered credentials from disk
func loadCachedCredentials(storagePath string) (*CachedCredentials, error) {
	if storagePath == "" {
		return nil, fmt.Errorf("storage path not configured")
	}

	data, err := os.ReadFile(storagePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no cached credentials found")
		}
		return nil, fmt.Errorf("failed to read cached credentials: %w", err)
	}

	var creds CachedCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached credentials: %w", err)
	}

	// Check if client secret has expired
	if creds.ClientSecretExpiresAt > 0 {
		expiresAt := time.Unix(creds.ClientSecretExpiresAt, 0)
		if time.Now().After(expiresAt) {
			return nil, fmt.Errorf("cached credentials expired at %s", expiresAt)
		}
	}

	return &creds, nil
}

// saveCachedCredentials saves dynamically registered credentials to disk
func saveCachedCredentials(storagePath string, regResp *RegistrationResponse) error {
	if storagePath == "" {
		return nil // Storage not configured, skip caching
	}

	creds := CachedCredentials{
		ClientID:                regResp.ClientID,
		ClientSecret:            regResp.ClientSecret,
		RegistrationAccessToken: regResp.RegistrationAccessToken,
		RegistrationClientURI:   regResp.RegistrationClientURI,
		ClientSecretExpiresAt:   regResp.ClientSecretExpiresAt,
		CachedAt:                time.Now(),
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	if err := os.WriteFile(storagePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials to %s: %w", storagePath, err)
	}

	return nil
}
