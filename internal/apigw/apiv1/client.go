package apiv1

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"time"
	"vc/internal/apigw/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"
	"vc/pkg/trace"
	"vc/pkg/vcclient"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

//	@title		Datastore API
//	@version	2.8
//	@BasePath	/api/v1

// Client holds the public api object
type Client struct {
	cfg                         *model.Cfg
	db                          *db.Service
	log                         *logger.Log
	tracer                      *trace.Tracer
	datastoreClient             *vcclient.Client
	issuerMetadata              *openid4vci.CredentialIssuerMetadataParameters
	issuerMetadataSigningKey    any
	issuerMetadataSigningCert   *x509.Certificate
	issuerMetadataSigningChain  []string
	oauth2Metadata              *oauth2.AuthorizationServerMetadata
	oauth2MetadataSigningKey    any
	oauth2MetadataSigningChain  []string
	ephemeralEncryptionKeyCache *ttlcache.Cache[string, jwk.Key]
	svgTemplateCache            *ttlcache.Cache[string, SVGTemplateReply]
	documentCache               *ttlcache.Cache[string, map[string]model.CompleteDocument]
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, tracer *trace.Tracer, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:                         cfg,
		db:                          db,
		log:                         log.New("apiv1"),
		tracer:                      tracer,
		ephemeralEncryptionKeyCache: ttlcache.New(ttlcache.WithTTL[string, jwk.Key](10 * time.Minute)),
		svgTemplateCache:            ttlcache.New(ttlcache.WithTTL[string, SVGTemplateReply](2 * time.Hour)),
		documentCache:               ttlcache.New(ttlcache.WithTTL[string, map[string]model.CompleteDocument](5 * time.Minute)),
	}

	// Start the ephemeral encryption key cache
	go c.ephemeralEncryptionKeyCache.Start()

	// Delete expired cache items automatically
	go c.svgTemplateCache.Start()

	go c.documentCache.Start()

	var err error
	if c.cfg.APIGW.IssuerMetadata.Path != "" {
		c.issuerMetadata, c.issuerMetadataSigningKey, c.issuerMetadataSigningCert, c.issuerMetadataSigningChain, err = c.cfg.APIGW.IssuerMetadata.LoadAndSign(ctx)
		if err != nil {
			return nil, err
		}
	}

	if c.cfg.APIGW.OauthServer.Metadata.Path != "" {
		c.oauth2Metadata, c.oauth2MetadataSigningKey, c.oauth2MetadataSigningChain, err = c.cfg.APIGW.OauthServer.LoadOAuth2Metadata(ctx)
		if err != nil {
			return nil, err
		}
	}

	// Specifies the issuer configuration based on the issuer identifier, should be initialized in main I guess.
	issuerIdentifier := cfg.Issuer.Identifier
	issuerCFG := cfg.AuthenticSources[issuerIdentifier]

	c.datastoreClient, err = vcclient.New(&vcclient.Config{URL: issuerCFG.AuthenticSourceEndpoint.URL})
	if err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}

// EphemeralEncryptionKey generates a new ephemeral encryption key pair, return private and public JWKs and KID, or error
func (c *Client) EphemeralEncryptionKey(kid string) (jwk.Key, jwk.Key, error) {
	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privateJWK, err := jwk.Import(privKey)
	if err != nil {
		return nil, nil, err
	}
	if err := privateJWK.Set("kid", kid); err != nil {
		return nil, nil, err
	}

	c.ephemeralEncryptionKeyCache.Set(kid, privateJWK, ttlcache.DefaultTTL)

	pub := privKey.Public()

	publicJWK, err := jwk.Import(pub)
	if err != nil {
		return nil, nil, err
	}

	if err := publicJWK.Set("use", "enc"); err != nil {
		return nil, nil, err
	}

	if err := publicJWK.Set("kid", kid); err != nil {
		return nil, nil, err
	}

	return privateJWK, publicJWK, nil
}
