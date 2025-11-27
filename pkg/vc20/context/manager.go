//go:build vc20

package context

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"vc/pkg/vc20/credential"
)

// ContextDocument represents a JSON-LD context document
type ContextDocument struct {
	URL      string
	Document map[string]interface{}
	Hash     string
	FetchedAt time.Time
}

// Manager handles caching and validation of JSON-LD context documents
type Manager struct {
	cache      map[string]*ContextDocument
	mu         sync.RWMutex
	httpClient *http.Client
	cacheTTL   time.Duration
}

// NewManager creates a new context manager
func NewManager() *Manager {
	return &Manager{
		cache: make(map[string]*ContextDocument),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cacheTTL: 24 * time.Hour, // Cache contexts for 24 hours
	}
}

// NewManagerWithClient creates a new context manager with a custom HTTP client
func NewManagerWithClient(client *http.Client, cacheTTL time.Duration) *Manager {
	return &Manager{
		cache:      make(map[string]*ContextDocument),
		httpClient: client,
		cacheTTL:   cacheTTL,
	}
}

// Get retrieves a context document, fetching it if not cached
func (m *Manager) Get(url string) (*ContextDocument, error) {
	// Check cache first
	m.mu.RLock()
	if doc, ok := m.cache[url]; ok {
		// Check if cache is still valid
		if time.Since(doc.FetchedAt) < m.cacheTTL {
			m.mu.RUnlock()
			return doc, nil
		}
	}
	m.mu.RUnlock()

	// Fetch the context document
	doc, err := m.fetch(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch context: %w", err)
	}

	// Cache the document
	m.mu.Lock()
	m.cache[url] = doc
	m.mu.Unlock()

	return doc, nil
}

// fetch retrieves a context document from a URL
func (m *Manager) fetch(url string) (*ContextDocument, error) {
	resp, err := m.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var document map[string]interface{}
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Compute SHA-256 hash
	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	return &ContextDocument{
		URL:       url,
		Document:  document,
		Hash:      hashStr,
		FetchedAt: time.Now(),
	}, nil
}

// ValidateBaseContext validates the base VC 2.0 context
func (m *Manager) ValidateBaseContext() error {
	doc, err := m.Get(credential.VC20ContextURL)
	if err != nil {
		return fmt.Errorf("failed to get base context: %w", err)
	}

	if doc.Hash != credential.VC20ContextHash {
		return fmt.Errorf("%w: expected %s, got %s",
			credential.ErrContextHashMismatch,
			credential.VC20ContextHash,
			doc.Hash)
	}

	return nil
}

// ValidateContexts validates all context URLs in a credential
func (m *Manager) ValidateContexts(contextURLs []string) error {
	if len(contextURLs) == 0 {
		return credential.ErrMissingContext
	}

	// First context must be the base VC 2.0 context
	if contextURLs[0] != credential.VC20ContextURL {
		return credential.ErrInvalidBaseContext
	}

	// Validate the base context hash
	if err := m.ValidateBaseContext(); err != nil {
		return err
	}

	// Fetch and cache all other contexts
	for i := 1; i < len(contextURLs); i++ {
		if _, err := m.Get(contextURLs[i]); err != nil {
			return fmt.Errorf("failed to validate context %s: %w", contextURLs[i], err)
		}
	}

	return nil
}

// Preload loads a context document into the cache
func (m *Manager) Preload(url string, document map[string]interface{}) error {
	data, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}

	hash := sha256.Sum256(data)
	hashStr := hex.EncodeToString(hash[:])

	m.mu.Lock()
	defer m.mu.Unlock()

	m.cache[url] = &ContextDocument{
		URL:       url,
		Document:  document,
		Hash:      hashStr,
		FetchedAt: time.Now(),
	}

	return nil
}

// Clear removes all cached context documents
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache = make(map[string]*ContextDocument)
}

// ClearExpired removes expired context documents from the cache
func (m *Manager) ClearExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for url, doc := range m.cache {
		if now.Sub(doc.FetchedAt) >= m.cacheTTL {
			delete(m.cache, url)
		}
	}
}

// Size returns the number of cached context documents
func (m *Manager) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cache)
}
