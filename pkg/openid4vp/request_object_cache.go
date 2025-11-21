package openid4vp

import (
	"time"

	"github.com/jellydator/ttlcache/v3"
)

const (
	// DefaultRequestObjectTTL is the default TTL for request objects
	DefaultRequestObjectTTL = 10 * time.Minute
)

// RequestObjectCache manages short-lived request objects for authorization requests
type RequestObjectCache struct {
	cache *ttlcache.Cache[string, *RequestObject]
}

// NewRequestObjectCache creates and starts a new request object cache
// with the specified TTL. Request objects are automatically evicted after the TTL expires.
func NewRequestObjectCache(ttl time.Duration) *RequestObjectCache {
	cache := ttlcache.New(
		ttlcache.WithTTL[string, *RequestObject](ttl),
	)

	// Start automatic expiration
	go cache.Start()

	return &RequestObjectCache{
		cache: cache,
	}
}

// Get retrieves a request object by its request URI
func (r *RequestObjectCache) Get(requestURI string) (*RequestObject, bool) {
	item := r.cache.Get(requestURI)
	if item == nil {
		return nil, false
	}
	return item.Value(), true
}

// Set stores a request object with the specified request URI
func (r *RequestObjectCache) Set(requestURI string, requestObject *RequestObject) {
	r.cache.Set(requestURI, requestObject, ttlcache.DefaultTTL)
}

// SetWithTTL stores a request object with a custom TTL
func (r *RequestObjectCache) SetWithTTL(requestURI string, requestObject *RequestObject, ttl time.Duration) {
	r.cache.Set(requestURI, requestObject, ttl)
}

// Delete removes a request object from the cache
func (r *RequestObjectCache) Delete(requestURI string) {
	r.cache.Delete(requestURI)
}

// Stop stops the cache's automatic expiration goroutine
func (r *RequestObjectCache) Stop() {
	r.cache.Stop()
}

// Len returns the number of items currently in the cache
func (r *RequestObjectCache) Len() int {
	return r.cache.Len()
}
