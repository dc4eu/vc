package apiv1

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"
	"vc/pkg/helpers"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// OIDCAuth  https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-endpoint
func (c *Client) OAuthPar(ctx context.Context, req *openid4vci.PARRequest) (*openid4vci.ParResponse, error) {
	c.log.Debug("OAuthPar", "req", req)
	if !c.cfg.APIGW.OauthServer.Clients.Allow(req.ClientID, req.RedirectURI, req.Scope) {
		return nil, oauth2.ErrInvalidClient
	}

	c.log.Debug("par")

	requestURI := fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", uuid.NewString())

	c.log.Debug("PAR", "state", req.State)

	azt := model.AuthorizationContext{
		//VerifierContextID:        oauth2.GenerateCryptographicNonceWithLength(32),
		SessionID:                uuid.NewString(),
		Code:                     uuid.NewString(),
		RequestURI:               requestURI,
		Scope:                    req.Scope,
		IsUsed:                   false,
		CodeChallenge:            req.CodeChallenge,
		CodeChallengeMethod:      req.CodeChallengeMethod,
		State:                    req.State,
		ClientID:                 req.ClientID,
		WalletURI:                req.RedirectURI,
		ExpiresAt:                time.Now().Add(60 * time.Second).Unix(),
		Nonce:                    oauth2.GenerateCryptographicNonceFixedLength(32),
		EphemeralEncryptionKeyID: oauth2.GenerateCryptographicNonceFixedLength(32),
		VerifierResponseCode:     oauth2.GenerateCryptographicNonceFixedLength(32),
	}

	if err := c.db.VCAuthorizationContextColl.Save(ctx, &azt); err != nil {
		c.log.Error(err, "save error")
		return nil, err
	}

	c.log.Debug("save success")

	response := &openid4vci.ParResponse{
		RequestURI: requestURI,
		ExpiresIn:  60,
	}

	return response, nil
}

func (c *Client) OAuthAuthorize(ctx context.Context, req *openid4vci.AuthorizeRequest) (*openid4vci.AuthorizationResponse, error) {
	c.log.Debug("Authorize", "req", req)
	query := &model.AuthorizationContext{
		RequestURI: req.RequestURI,
		ClientID:   req.ClientID,
	}
	authorizationContext, err := c.db.VCAuthorizationContextColl.Get(ctx, query)
	c.log.Debug("Get authorization", "query", query, "authorization", authorizationContext)
	if err != nil {
		c.log.Error(err, "get error")
		return nil, err
	}
	c.log.Debug("Authorization", "state", authorizationContext.State)

	if authorizationContext.IsUsed {
		c.log.Debug("Authorization already used")
		return nil, errors.New("not allowed")
	}

	var redirectURL string
	if !authorizationContext.Consent {
		redirectURL = "/authorization/consent"
	}

	response := &openid4vci.AuthorizationResponse{
		RedirectURL: redirectURL,
		Scope:       authorizationContext.Scope,
		SessionID:   authorizationContext.SessionID,
		ClientID:    authorizationContext.ClientID,
	}

	c.log.Debug("Authorize", "authorization", authorizationContext)

	return response, nil
}

// OIDCToken https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-token-endpoint
func (c *Client) OAuthToken(ctx context.Context, req *openid4vci.TokenRequest) (*openid4vci.TokenResponse, error) {
	c.log.Debug("OIDCToken", "req", req)

	authorizationContext, err := c.db.VCAuthorizationContextColl.ForfeitAuthorizationCode(ctx, &model.AuthorizationContext{
		Code: req.Code,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization")
		return nil, err
	}
	c.log.Debug("Token", "state", authorizationContext.State)

	// generating a new access token
	accessToken := oauth2.GenerateCryptographicNonceFixedLength(32)
	c.log.Debug("Generated access token", "access_token", accessToken)

	// Bind the public key to the generated access token

	reply := &openid4vci.TokenResponse{
		AccessToken:          accessToken,
		TokenType:            "DPoP",
		ExpiresIn:            3600, // 1 hour
		Scope:                authorizationContext.Scope,
		State:                authorizationContext.State,
		CNonce:               authorizationContext.Nonce,
		CNonceExpiresIn:      0,
		AuthorizationDetails: []openid4vci.AuthorizationDetailsParameter{},
	}

	tokenDoc := &model.Token{
		AccessToken: accessToken,
		ExpiresAt:   time.Now().Add(time.Duration(reply.ExpiresIn) * time.Second).Unix(),
	}

	if err := c.db.VCAuthorizationContextColl.AddToken(ctx, authorizationContext.Code, tokenDoc); err != nil {
		c.log.Error(err, "failed to add token")
		return nil, err
	}

	dpop, err := oauth2.ValidateAndParseDPoPJWT(req.Header.DPOP)
	if err != nil {
		c.log.Error(err, "dpop validation error")
		return nil, err
	}

	if dpop.HTU != c.cfg.APIGW.OauthServer.TokenEndpoint {
		return nil, fmt.Errorf("invalid HTU in DPoP claims: %s", dpop.HTU)
	}
	if dpop.HTM != "POST" {
		return nil, fmt.Errorf("invalid HTM in DPoP claims: %s", dpop.HTM)
	}

	c.log.Debug("DPoP claims", "jti", dpop.JTI, "htu", dpop.HTU, "htm", dpop.HTM)

	//base64(sha256(code_verifier)) == stored code_challenge

	//c.db.VCAuthColl.Grant(ctx, req.ClientID, req.Code)

	// Check if ClientID and Code match
	// Check if Code have been used
	// Check if Code is expired
	return reply, nil
}

func (c *Client) OAuthMetadata(ctx context.Context) (*oauth2.AuthorizationServerMetadata, error) {
	c.log.Debug("metadata request")

	signedMetadata, err := c.oauth2Metadata.Sign(jwt.SigningMethodRS256, c.oauth2MetadataSigningKey, c.oauth2MetadataSigningChain)
	if err != nil {
		return nil, err
	}

	if err := helpers.Check(ctx, c.cfg, signedMetadata, c.log); err != nil {
		c.log.Error(err, "metadata check error")
		return nil, err
	}

	return signedMetadata, nil
}

type OauthAuthorizationConsentRequest struct {
	//AuthMethod string `json:"-"`
	SessionID string `json:"-"`
}

type OAuthAuthorizationConsentResponse struct {
	RedirectURL       string
	VerifierContextID string `json:"-"`
}

func (c *Client) OAuthAuthorizationConsent(ctx context.Context, req *OauthAuthorizationConsentRequest) (*OAuthAuthorizationConsentResponse, error) {
	authorizationContext, err := c.db.VCAuthorizationContextColl.Get(ctx, &model.AuthorizationContext{SessionID: req.SessionID})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return nil, err
	}
	c.log.Debug("Authorization/consent", "state", authorizationContext.State)

	c.log.Debug("OAuthAuthorizationConsent request")

	verifierRequestURI, err := url.Parse("https://vc-interop-3.sunet.se/verification/request-object")
	if err != nil {
		c.log.Error(err, "failed to parse request URI URL")
		return nil, err
	}

	requestURI := url.Values{
		"id": []string{authorizationContext.VerifierResponseCode},
	}

	verifierRequestURI.RawQuery = requestURI.Encode()

	u, err := url.Parse(authorizationContext.WalletURI)
	if err != nil {
		c.log.Error(err, "failed to parse URL")
		return nil, err
	}
	values := url.Values{
		"client_id":   []string{authorizationContext.ClientID},
		"request_uri": []string{verifierRequestURI.String()},
	}

	u.RawQuery = values.Encode()

	reply := &OAuthAuthorizationConsentResponse{
		RedirectURL:       u.String(),
		VerifierContextID: authorizationContext.VerifierResponseCode,
	}

	c.log.Debug("OAuthAuthorizationConsent response", "redirectURL", reply.RedirectURL)

	return reply, nil
}

type OauthAuthorizationConsentCallbackRequest struct {
	ResponseCode string `json:"response_code" form:"response_code" uri:"response_code"`
}

type OAuthAuthorizationConsentCallbackResponse struct {
	//RedirectURL string `json:"-"`
}

func (c *Client) OAuthAuthorizationConsentCallback(ctx context.Context, req *OauthAuthorizationConsentCallbackRequest) (*OAuthAuthorizationConsentCallbackResponse, error) {
	c.log.Debug("OAuthAuthorizationConsentCallback request", "req", req)
	reply := &OAuthAuthorizationConsentCallbackResponse{}

	return reply, nil
}
