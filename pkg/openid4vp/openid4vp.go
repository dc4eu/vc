package openid4vp

import (
	"context"
	"time"
)

// Client holds the OpenID4VP client with ephemeral key caching and request object caching
type Client struct {
	EphemeralKeyCache  *EphemeralEncryptionKeyCache
	RequestObjectCache *RequestObjectCache
}

// Config holds configuration for the OpenID4VP client
type Config struct {
	// EphemeralKeyTTL specifies the TTL for ephemeral encryption keys.
	// If not set or zero, DefaultEphemeralKeyTTL (10 minutes) is used.
	EphemeralKeyTTL time.Duration

	// RequestObjectTTL specifies the TTL for request objects.
	// If not set or zero, DefaultRequestObjectTTL (10 minutes) is used.
	RequestObjectTTL time.Duration
}

// New creates a new OpenID4VP client with ephemeral key cache and request object cache
func New(ctx context.Context, config *Config) (*Client, error) {
	ephemeralKeyCacheTTL := DefaultEphemeralKeyTTL
	requestObjectCacheTTL := DefaultRequestObjectTTL

	if config != nil {
		if config.EphemeralKeyTTL > 0 {
			ephemeralKeyCacheTTL = config.EphemeralKeyTTL
		}
		if config.RequestObjectTTL > 0 {
			requestObjectCacheTTL = config.RequestObjectTTL
		}
	}

	client := &Client{
		EphemeralKeyCache:  NewEphemeralEncryptionKeyCache(ephemeralKeyCacheTTL),
		RequestObjectCache: NewRequestObjectCache(requestObjectCacheTTL),
	}

	return client, nil
}

// Close stops the ephemeral key cache and request object cache
func (c *Client) Close() {
	if c.EphemeralKeyCache != nil {
		c.EphemeralKeyCache.Stop()
	}
	if c.RequestObjectCache != nil {
		c.RequestObjectCache.Stop()
	}
}
