package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/gen/registry/apiv1_registry"
	"vc/internal/issuer/auditlog"
	"vc/pkg/grpchelpers"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/mdoc"
	"vc/pkg/model"
	"vc/pkg/signing"
	"vc/pkg/trace"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
)

//	@title		Issuer API
//	@version	0.1.0
//	@BasePath	/issuer/api/v1

// Client holds the public api object
type Client struct {
	cfg            *model.Cfg
	log            *logger.Log
	tracer         *trace.Tracer
	auditLog       *auditlog.Service
	signer         signing.Signer
	privateKey     any // Can be *ecdsa.PrivateKey or *rsa.PrivateKey (legacy, kept for JWK creation)
	publicKey      any // Can be *ecdsa.PublicKey or *rsa.PublicKey
	jwkClaim       jwt.MapClaims
	jwkBytes       []byte
	jwkProto       *apiv1_issuer.Jwk
	kid            string
	registryConn   *grpc.ClientConn
	registryClient apiv1_registry.RegistryServiceClient
	mdocIssuer     *mdoc.Issuer // mDL issuer for ISO 18013-5 credentials
}

// New creates a new instance of the public api
func New(ctx context.Context, auditLog *auditlog.Service, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:      cfg,
		log:      log.New("apiv1"),
		tracer:   tracer,
		auditLog: auditLog,
		jwkProto: &apiv1_issuer.Jwk{},
		jwkClaim: jwt.MapClaims{},
	}

	if err := c.initSigner(ctx); err != nil {
		return nil, err
	}

	if err := c.initRegistryClient(ctx); err != nil {
		return nil, err
	}

	for scope, credentialInfo := range cfg.CredentialConstructor {
		if err := credentialInfo.LoadVCTMetadata(ctx, scope); err != nil {
			c.log.Error(err, "Failed to load credential constructor", "scope", scope)
			return nil, err
		}

		credentialInfo.Attributes = credentialInfo.VCTM.Attributes()
	}

	// Initialize mDL issuer if certificate chain is configured
	if err := c.initMDocIssuer(ctx); err != nil {
		c.log.Info("mDL issuer not initialized", "error", err)
		// Non-fatal: mDL issuance will be unavailable but SD-JWT will work
	}

	c.log.Info("Started")

	return c, nil
}

// initSigner initializes the signing service (software or PKCS#11)
func (c *Client) initSigner(ctx context.Context) error {
	// Check if PKCS#11 is configured
	if c.cfg.Issuer.PKCS11 != nil {
		return c.initPKCS11Signer(ctx)
	}

	// Fall back to software signer
	return c.initSoftwareSigner(ctx)
}

// initPKCS11Signer initializes a PKCS#11 HSM signer
func (c *Client) initPKCS11Signer(ctx context.Context) error {
	pkcs11Cfg := c.cfg.Issuer.PKCS11

	signer, err := signing.NewPKCS11Signer(&signing.PKCS11Config{
		ModulePath: pkcs11Cfg.ModulePath,
		SlotID:     pkcs11Cfg.SlotID,
		PIN:        pkcs11Cfg.PIN,
		KeyLabel:   pkcs11Cfg.KeyLabel,
		KeyID:      pkcs11Cfg.KeyID,
	})
	if err != nil {
		c.log.Error(err, "Failed to initialize PKCS#11 signer")
		return fmt.Errorf("failed to initialize PKCS#11 signer: %w", err)
	}

	c.signer = signer
	c.publicKey = signer.PublicKey()
	c.kid = signer.KeyID()

	c.log.Info("Initialized PKCS#11 signer", "keyID", c.kid)

	if err := c.createJWK(ctx); err != nil {
		return err
	}

	return nil
}

// initSoftwareSigner initializes a software key signer
func (c *Client) initSoftwareSigner(ctx context.Context) error {
	keyByte, err := os.ReadFile(c.cfg.Issuer.SigningKeyPath)
	if err != nil {
		c.log.Error(err, "Failed to read signing key")
		return err
	}

	if keyByte == nil {
		return helpers.ErrPrivateKeyMissing
	}

	// Parse the private key
	c.privateKey, err = c.parsePrivateKey(keyByte)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Extract public key based on key type
	switch key := c.privateKey.(type) {
	case *ecdsa.PrivateKey:
		c.publicKey = &key.PublicKey
	case *rsa.PrivateKey:
		c.publicKey = &key.PublicKey
	default:
		return fmt.Errorf("unsupported key type: %T", c.privateKey)
	}

	// Create JWK first to get the kid
	if err := c.createJWK(ctx); err != nil {
		return err
	}

	// Create software signer
	c.signer, err = signing.NewSoftwareSigner(c.privateKey, c.kid)
	if err != nil {
		return fmt.Errorf("failed to create software signer: %w", err)
	}

	c.log.Info("Initialized software signer", "keyID", c.kid)

	return nil
}

// parsePrivateKey attempts to parse a private key from PEM format
// Supports ECDSA and RSA keys in various formats (PKCS8, PKCS1, EC)
func (c *Client) parsePrivateKey(keyByte []byte) (any, error) {
	block, _ := pem.Decode(keyByte)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS8 format first (preferred, supports both RSA and ECDSA)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try EC private key format
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS1 RSA private key format
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try using jwt library's parser as fallback for EC keys
	if key, err := jwt.ParseECPrivateKeyFromPEM(keyByte); err == nil {
		return key, nil
	}

	// Try using jwt library's parser as fallback for RSA keys
	if key, err := jwt.ParseRSAPrivateKeyFromPEM(keyByte); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("unable to parse private key in any supported format")
}

// initRegistryClient initializes the gRPC client connection to the registry service
func (c *Client) initRegistryClient(ctx context.Context) error {
	cfg := c.cfg.Issuer.RegistryClient
	if cfg.Addr == "" {
		c.log.Info("Registry client not configured, skipping initialization")
		return nil
	}

	conn, err := grpchelpers.NewClientConn(cfg)
	if err != nil {
		return fmt.Errorf("failed to create registry client connection: %w", err)
	}

	c.registryConn = conn
	c.registryClient = apiv1_registry.NewRegistryServiceClient(conn)

	c.log.Info("Registry client initialized", "addr", cfg.Addr, "tls_enabled", cfg.TLS)
	return nil
}

// initMDocIssuer initializes the mDL issuer for ISO 18013-5 credentials
func (c *Client) initMDocIssuer(ctx context.Context) error {
	// Check if mDL configuration is available
	if c.cfg.Issuer.MDoc == nil {
		return fmt.Errorf("mDL configuration not found")
	}

	mdocCfg := c.cfg.Issuer.MDoc

	// Read and parse the certificate chain
	if mdocCfg.CertificateChainPath == "" {
		return fmt.Errorf("certificate chain path not configured for mDL")
	}

	certChain, err := c.loadCertificateChain(mdocCfg.CertificateChainPath)
	if err != nil {
		return fmt.Errorf("failed to load certificate chain: %w", err)
	}

	// Get the signing key - reuse the existing private key if it's ECDSA
	var signerKey *ecdsa.PrivateKey
	switch key := c.privateKey.(type) {
	case *ecdsa.PrivateKey:
		signerKey = key
	default:
		return fmt.Errorf("mDL requires ECDSA signing key, got %T", c.privateKey)
	}

	// Create the mDL issuer
	issuer, err := mdoc.NewIssuer(mdoc.IssuerConfig{
		SignerKey:        signerKey,
		CertificateChain: certChain,
		DefaultValidity:  mdocCfg.DefaultValidity,
		DigestAlgorithm:  mdoc.DigestAlgorithm(mdocCfg.DigestAlgorithm),
	})
	if err != nil {
		return fmt.Errorf("failed to create mDL issuer: %w", err)
	}

	c.mdocIssuer = issuer
	c.log.Info("mDL issuer initialized", "cert_chain_length", len(certChain))
	return nil
}

// loadCertificateChain loads X.509 certificates from a PEM file
func (c *Client) loadCertificateChain(path string) ([]*x509.Certificate, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(certPEM)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		certPEM = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in file")
	}

	return certs, nil
}

// Close closes all client connections
func (c *Client) Close() error {
	if c.registryConn != nil {
		return c.registryConn.Close()
	}
	return nil
}

// RegistryClient returns the registry gRPC client, may be nil if not configured
func (c *Client) RegistryClient() apiv1_registry.RegistryServiceClient {
	return c.registryClient
}
