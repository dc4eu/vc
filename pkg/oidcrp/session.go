//go:build oidcrp

package oidcrp

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"vc/pkg/logger"
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

// SessionStore manages OIDC RP sessions with automatic expiration
type SessionStore struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	duration time.Duration
	log      *logger.Log
}

// NewSessionStore creates a new session store
func NewSessionStore(duration time.Duration, log *logger.Log) *SessionStore {
	store := &SessionStore{
		sessions: make(map[string]*Session),
		duration: duration,
		log:      log.New("oidcrp_session"),
	}

	// Start cleanup goroutine
	go store.cleanup()

	return store
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

	session := &Session{
		ID:             state, // Use state as session ID for simplicity
		State:          state,
		Nonce:          nonce,
		CodeVerifier:   codeVerifier,
		CredentialType: credentialType,
		IssuerURL:      issuerURL,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(s.duration),
	}

	s.mu.Lock()
	s.sessions[session.ID] = session
	s.mu.Unlock()

	s.log.Debug("Session created",
		"session_id", session.ID,
		"credential_type", credentialType,
		"issuer", issuerURL)

	return session, nil
}

// Get retrieves a session by state parameter
func (s *SessionStore) Get(state string) (*Session, error) {
	s.mu.RLock()
	session, exists := s.sessions[state]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session not found for state: %s", state)
	}

	if time.Now().After(session.ExpiresAt) {
		s.Delete(state)
		return nil, fmt.Errorf("session expired for state: %s", state)
	}

	return session, nil
}

// Delete removes a session
func (s *SessionStore) Delete(state string) {
	s.mu.Lock()
	delete(s.sessions, state)
	s.mu.Unlock()

	s.log.Debug("Session deleted", "state", state)
}

// cleanup periodically removes expired sessions
func (s *SessionStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, session := range s.sessions {
			if now.After(session.ExpiresAt) {
				delete(s.sessions, id)
				s.log.Debug("Expired session cleaned up", "session_id", id)
			}
		}
		s.mu.Unlock()
	}
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes)[:length], nil
}
