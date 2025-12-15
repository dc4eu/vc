package tslissuer

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jellydator/ttlcache/v3"

	"vc/internal/registry/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/pki"
	"vc/pkg/tsl"
)

// Service is the status list issuer service
type Service struct {
	cfg                *model.Cfg
	statusListColl     db.StatusListStore
	statusListMetadata db.StatusListMetadataStore
	signingKey         any // Can be *ecdsa.PrivateKey or *rsa.PrivateKey
	log                *logger.Log

	// Caches for JWT and CWT tokens keyed by section (as string)
	jwtCache *ttlcache.Cache[string, string]
	cwtCache *ttlcache.Cache[string, []byte]

	// refreshInterval is how often tokens are regenerated
	refreshInterval time.Duration
	// tokenValidity is how long tokens are valid (slightly longer than refresh)
	tokenValidity time.Duration
	// ttl is the TTL claim value in tokens (seconds)
	ttl int64

	// stopCh signals the refresh goroutine to stop
	stopCh chan struct{}
}

// New creates a new status list issuer service
func New(ctx context.Context, cfg *model.Cfg, dbService *db.Service, log *logger.Log) (*Service, error) {
	refreshSeconds := cfg.Registry.TokenStatusLists.TokenRefreshInterval
	if refreshSeconds <= 0 {
		refreshSeconds = 43200 // default 12 hours per spec example (Section 5.1)
	}
	refreshInterval := time.Duration(refreshSeconds) * time.Second
	// Token validity equals refresh interval minus buffer for regeneration time
	tokenValidity := refreshInterval - (5 * time.Minute)

	s := &Service{
		cfg:                cfg,
		statusListColl:     dbService.TSLColl,
		statusListMetadata: dbService.TSLMetadata,
		log:                log.New("tsl_issuer"),
		jwtCache:           ttlcache.New(ttlcache.WithTTL[string, string](tokenValidity)),
		cwtCache:           ttlcache.New(ttlcache.WithTTL[string, []byte](tokenValidity)),
		refreshInterval:    refreshInterval,
		tokenValidity:      tokenValidity,
		ttl:                refreshSeconds,
		stopCh:             make(chan struct{}),
	}

	// Load signing key
	key, err := pki.ParseKeyFromFile(cfg.Registry.TokenStatusLists.SigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TSL signing key: %w", err)
	}
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("TSL signing key is not a valid ECDSA private key, path: %s", cfg.Registry.TokenStatusLists.SigningKeyPath)
	}
	s.signingKey = privateKey
	s.log.Info("Loaded TSL signing key", "path", cfg.Registry.TokenStatusLists.SigningKeyPath)

	// Initialize database if empty
	if err := s.statusListColl.InitializeIfEmpty(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize status list database: %w", err)
	}

	// Start cache cleanup goroutines
	go s.jwtCache.Start()
	go s.cwtCache.Start()

	// Start the refresh goroutine
	go s.refreshLoop(ctx)

	s.log.Info("Started TSL cache refresh", "interval", refreshInterval, "validity", tokenValidity)

	return s, nil
}

// Close closes the status issuer service
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Closing status issuer service")
	close(s.stopCh)
	s.jwtCache.Stop()
	s.cwtCache.Stop()
	return nil
}

// GetCachedJWT returns a cached JWT for the given section, or empty string if not cached
func (s *Service) GetCachedJWT(section int64) string {
	key := strconv.FormatInt(section, 10)
	item := s.jwtCache.Get(key)
	if item == nil {
		return ""
	}
	return item.Value()
}

// GetCachedCWT returns a cached CWT for the given section, or nil if not cached
func (s *Service) GetCachedCWT(section int64) []byte {
	key := strconv.FormatInt(section, 10)
	item := s.cwtCache.Get(key)
	if item == nil {
		return nil
	}
	return item.Value()
}

// refreshLoop periodically refreshes all cached status list tokens
func (s *Service) refreshLoop(ctx context.Context) {
	// Do initial refresh immediately
	s.refreshAllSections(ctx)

	ticker := time.NewTicker(s.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.log.Info("Cache refresh loop: context done")
			return
		case <-s.stopCh:
			s.log.Info("Cache refresh loop: stop signal received")
			return
		case <-ticker.C:
			s.refreshAllSections(ctx)
		}
	}
}

// refreshAllSections refreshes the cache for all available sections
func (s *Service) refreshAllSections(ctx context.Context) {
	sections, err := s.statusListMetadata.GetAllSections(ctx)
	if err != nil {
		s.log.Error(err, "Failed to get sections for cache refresh")
		return
	}

	for _, section := range sections {
		s.refreshSection(ctx, section)
	}

	s.log.Debug("Cache refresh completed", "sections", len(sections))
}

// refreshSection refreshes the cache for a single section
func (s *Service) refreshSection(ctx context.Context, section int64) {
	statuses, err := s.statusListColl.GetAllStatusesForSection(ctx, section)
	if err != nil {
		s.log.Error(err, "Failed to get statuses for section", "section", section)
		return
	}

	if len(statuses) == 0 {
		return
	}

	key := strconv.FormatInt(section, 10)

	// Build URIs using registry's external server URL
	baseURL := s.cfg.Registry.ExternalServerURL
	subject := baseURL + "/statuslists/" + key
	issuer := baseURL

	// Token config
	tokenCfg := TokenConfig{
		TokenConfig: tsl.TokenConfig{
			Subject:   subject,
			Issuer:    issuer,
			Statuses:  statuses,
			TTL:       s.ttl,
			ExpiresIn: s.tokenValidity,
		},
		SigningMethod: jwt.SigningMethodES256,
	}

	// Generate and cache JWT
	jwtToken, err := s.GenerateStatusListTokenJWT(ctx, tokenCfg)
	if err != nil {
		s.log.Error(err, "Failed to generate JWT", "section", section)
	} else {
		s.jwtCache.Set(key, jwtToken, ttlcache.DefaultTTL)
	}

	// Generate and cache CWT
	cwtToken, err := s.GenerateStatusListTokenCWT(ctx, tokenCfg)
	if err != nil {
		s.log.Error(err, "Failed to generate CWT", "section", section)
	} else {
		s.cwtCache.Set(key, cwtToken, ttlcache.DefaultTTL)
	}
}
