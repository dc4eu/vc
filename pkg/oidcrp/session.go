//go:build oidcrp

package oidcrp

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"vc/pkg/logger"

	"github.com/jellydator/ttlcache/v3"
)

// Session represents an OIDC authentication session
type Session struct {
	ID             string
	State          string // OAuth2 state parameter (CSRF protection)
	Nonce          string // OIDC nonce for ID token validation
	CodeVerifier   string // PKCE code_verifier
	CredentialType string // Requested credential type
	IssuerURL      string // OIDC Provider issuer URL
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// SessionStore manages OIDC RP sessions with automatic expiration using ttlcache
type SessionStore struct {
	cache    *ttlcache.Cache[string, *Session]
	duration time.Duration
	log      *logger.Log
}

// NewSessionStore creates a new session store using ttlcache
func NewSessionStore(duration time.Duration, log *logger.Log) *SessionStore {
	cache := ttlcache.New(
		ttlcache.WithTTL[string, *Session](duration),
	)

	go cache.Start() // Start automatic cleanup

	return &SessionStore{
		cache:    cache,
		duration: duration,
		log:      log.New("oidcrp_session"),
	}
}

// Create creates a new session with generated state, nonce, and code_verifier
func (s *SessionStore) Create(credentialType, issuerURL string) (*Session, error) {
	state, err := generateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	nonce, err := generateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	codeVerifier, err := generateRandomString(43) // PKCE verifier 43-128 chars
	if err != nil {
		return nil, fmt.Errorf("failed to generate code_verifier: %w", err)
	}

	now := time.Now()
	session := &Session{
		ID:             state, // Use state as session ID for simplicity
		State:          state,
		Nonce:          nonce,
		CodeVerifier:   codeVerifier,
		CredentialType: credentialType,
		IssuerURL:      issuerURL,
		CreatedAt:      now,
		ExpiresAt:      now.Add(s.duration),
	}

	s.cache.Set(session.ID, session, ttlcache.DefaultTTL)

	s.log.Debug("Session created",
		"session_id", session.ID,
		"credential_type", credentialType,
		"issuer", issuerURL)

	return session, nil
}

// Get retrieves a session by state parameter
func (s *SessionStore) Get(state string) (*Session, error) {
	item := s.cache.Get(state)
	if item == nil {
		return nil, fmt.Errorf("session not found for state: %s", state)
	}

	session := item.Value()
	if session == nil {
		return nil, fmt.Errorf("session expired for state: %s", state)
	}

	return session, nil
}

// Delete removes a session
func (s *SessionStore) Delete(state string) {
	s.cache.Delete(state)
	s.log.Debug("Session deleted", "state", state)
}

// Stop stops the automatic cleanup goroutine
func (s *SessionStore) Stop() {
	s.cache.Stop()
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes)[:length], nil
}
