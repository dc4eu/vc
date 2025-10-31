package apiv1

import (
	"context"
	"crypto/x509"
	"time"
	"vc/internal/verifier/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vp"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Client holds the public api object
type Client struct {
	cfg                         *model.Cfg
	db                          *db.Service
	log                         *logger.Log
	oauth2Metadata              *oauth2.AuthorizationServerMetadata
	oauth2MetadataSigningKey    any
	oauth2MetadataSigningChain  []string
	issuerMetadataSigningKey    any
	issuerMetadataSigningCert   *x509.Certificate
	issuerMetadataSigningChain  []string
	ephemeralEncryptionKeyCache *ttlcache.Cache[string, jwk.Key]
	requestObjectCache          *ttlcache.Cache[string, *openid4vp.RequestObject]

	trustService *openid4vp.TrustService
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:                         cfg,
		db:                          db,
		log:                         log.New("apiv1"),
		ephemeralEncryptionKeyCache: ttlcache.New(ttlcache.WithTTL[string, jwk.Key](10 * time.Minute)),
		requestObjectCache:          ttlcache.New(ttlcache.WithTTL[string, *openid4vp.RequestObject](5 * time.Minute)),
	}

	// Start the ephemeral encryption key cache
	go c.ephemeralEncryptionKeyCache.Start()

	go c.requestObjectCache.Start()

	var err error
	if c.cfg.Verifier.OAuthServer.Metadata.Path != "" {
		c.oauth2Metadata, c.oauth2MetadataSigningKey, c.oauth2MetadataSigningChain, err = c.cfg.Verifier.OAuthServer.LoadOAuth2Metadata(ctx)
		if err != nil {
			return nil, err
		}
	}

	if c.cfg.Verifier.IssuerMetadata.Path != "" {
		_, c.issuerMetadataSigningKey, c.issuerMetadataSigningCert, c.issuerMetadataSigningChain, err = c.cfg.Verifier.IssuerMetadata.LoadAndSign(ctx)
		if err != nil {
			return nil, err
		}
	}

	// Load all vct metadata files and populate its data in cfg
	for vct, credentialInfo := range cfg.CredentialConstructor {
		if err := credentialInfo.LoadFile(ctx); err != nil {
			c.log.Error(err, "Failed to load credential constructor", "type", vct)
			return nil, err
		}

		credentialInfo.Attributes = credentialInfo.VCTM.Attributes()
	}

	c.trustService = &openid4vp.TrustService{}

	c.log.Info("Started")

	return c, nil
}
