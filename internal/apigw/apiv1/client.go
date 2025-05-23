package apiv1

import (
	"context"
	"vc/internal/apigw/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"
	"vc/pkg/trace"
	"vc/pkg/vcclient"
)

//	@title		Datastore API
//	@version	2.8
//	@BasePath	/api/v1

// Client holds the public api object
type Client struct {
	cfg                        *model.Cfg
	db                         *db.Service
	log                        *logger.Log
	tracer                     *trace.Tracer
	datastoreClient            *vcclient.Client
	issuerMetadata             *openid4vci.CredentialIssuerMetadataParameters
	issuerMetadataSigningKey   any
	issuerMetadataSigningChain []string
	oauth2Metadata             *oauth2.AuthorizationServerMetadata
	oauth2MetadataSigningKey   any
	oauth2MetadataSigningChain []string
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, tracer *trace.Tracer, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:    cfg,
		db:     db,
		log:    log.New("apiv1"),
		tracer: tracer,
	}

	var err error
	if c.cfg.APIGW.IssuerMetadata.Path != "" {
		c.issuerMetadata, c.issuerMetadataSigningKey, c.issuerMetadataSigningChain, err = c.cfg.LoadIssuerMetadata(ctx)
		if err != nil {
			return nil, err
		}
	}

	if c.cfg.APIGW.OauthServer.Metadata.Path != "" {
		c.oauth2Metadata, c.oauth2MetadataSigningKey, c.oauth2MetadataSigningChain, err = c.cfg.LoadOAuth2Metadata(ctx)
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
