package apiv1

import (
	"context"
	"crypto/x509"
	"time"
	"vc/internal/verifier/db"
	"vc/internal/verifier/notify"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vp"
	"vc/pkg/sdjwtvc"

	"github.com/jellydator/ttlcache/v3"
)

// Client holds the public api object
type Client struct {
	cfg                        *model.Cfg
	db                         *db.Service
	authContextStore           db.AuthorizationContextStore
	log                        *logger.Log
	notify                     *notify.Service
	oauth2Metadata             *oauth2.AuthorizationServerMetadata
	oauth2MetadataSigningKey   any
	oauth2MetadataSigningChain []string
	issuerMetadataSigningKey   any
	issuerMetadataSigningCert  *x509.Certificate
	issuerMetadataSigningChain []string
	openid4vp                  *openid4vp.Client
	credentialCache            *ttlcache.Cache[string, []sdjwtvc.CredentialCache]

	trustService *openid4vp.TrustService
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, notify *notify.Service, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	// Create OpenID4VP client with custom TTL settings
	openid4vpClient, err := openid4vp.New(ctx, &openid4vp.Config{
		EphemeralKeyTTL:  10 * time.Minute,
		RequestObjectTTL: 5 * time.Minute,
	})
	if err != nil {
		return nil, err
	}

	c := &Client{
		cfg:              cfg,
		db:               db,
		authContextStore: db.AuthorizationContextColl,
		log:              log.New("apiv1"),
		notify:           notify,
		openid4vp:        openid4vpClient,
		credentialCache:  ttlcache.New(ttlcache.WithTTL[string, []sdjwtvc.CredentialCache](5 * time.Minute)),
	}

	go c.credentialCache.Start()

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
	for scope, credentialInfo := range cfg.CredentialConstructor {
		if err := credentialInfo.LoadVCTMetadata(ctx, scope); err != nil {
			c.log.Error(err, "Failed to load credential constructor", "scope", scope)
			return nil, err
		}

		credentialInfo.Attributes = credentialInfo.VCTM.AttributesWithoutObjects()
	}

	c.trustService = &openid4vp.TrustService{}

	c.log.Info("Started")

	return c, nil
}
