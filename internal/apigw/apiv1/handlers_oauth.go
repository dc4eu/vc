package apiv1

import (
	"context"
	"errors"
	"fmt"
	"vc/pkg/helpers"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// return_uri presentation_definition
// after authorize

// OIDCAuth  https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-endpoint
func (c *Client) OAuthPar(ctx context.Context, req *openid4vci.PARRequest) (*openid4vci.ParResponse, error) {
	if !c.cfg.APIGW.OauthServer.Clients.Allow(req.ClientID, req.RedirectURI, req.Scope) {
		return nil, oauth2.ErrInvalidClient
	}

	c.log.Debug("par")
	c.log.Debug("req", "data", req)

	requestURI := fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", uuid.NewString())

	azt := model.Authorization{
		Code:                uuid.NewString(),
		RequestURI:          requestURI,
		IsUsed:              false,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		State:               req.State,
		ClientID:            req.ClientID,
	}

	if err := c.db.VCAuthzColl.Save(ctx, &azt); err != nil {
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
	query := &model.Authorization{
		RequestURI: req.RequestURI,
		ClientID:   req.ClientID,
	}
	authorization, err := c.db.VCAuthzColl.Get(ctx, query)
	c.log.Debug("Get authorization", "query", query, "authorization", authorization)
	if err != nil {
		c.log.Error(err, "get error")
		return nil, err
	}

	if authorization.IsUsed {
		return nil, errors.New("not allowed")
	}

	c.log.Debug("Authorize", "authorization", authorization)

	response := &openid4vci.AuthorizationResponse{
		Code:  authorization.Code,
		State: authorization.State,
	}

	return response, nil
}

// OAuthAuthorizeConsent collects user attributes
func (c *Client) OAuthAuthorizationConsent(ctx context.Context, req *openid4vci.AuthorizationConsentRequest) (*openid4vci.AuthorizationConsentReply, error) {
	c.log.Debug("OAuthAuthorizationConsent", "req", req)

	return nil, nil
}

// OAuthAuthorizeConsentLogin collects user attributes
func (c *Client) OAuthAuthorizationConsentLogin(ctx context.Context, req *openid4vci.AuthorizationConsentLoginRequest) (*openid4vci.AuthorizationConsentLoginReply, error) {
	c.log.Debug("OAuthAuthorizationConsentLogin", "req", req)

c.db.VCUsersColl.GetHashedPassword(ctx, req.Username)


	return nil, nil
}

// OIDCToken https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-token-endpoint
func (c *Client) OAuthToken(ctx context.Context, req *openid4vci.TokenRequest) (*openid4vci.TokenResponse, error) {
	c.log.Debug("OIDCToken")
	c.log.Debug("req", "data", req)

	query := &model.Authorization{
		Code: req.Code,
	}
	authorization, err := c.db.VCAuthzColl.Get(ctx, query)
	if err != nil {
		c.log.Error(err, "failed to get authorization")
		return nil, err
	}

	// generating a new access token
	accessToken, err := oauth2.GenerateCryptographicNonce(32)
	if err != nil {
		c.log.Error(err, "failed to generate access token")
		return nil, err
	}
	c.log.Debug("Generated access token", "access_token", accessToken)

	// Bind the public key to the generated access token

	reply := &openid4vci.TokenResponse{
		AccessToken:          accessToken,
		TokenType:            "DPoP",
		ExpiresIn:            3600, // 1 hour
		Scope:                "diploma",
		State:                authorization.State,
		CNonce:               "",
		CNonceExpiresIn:      0,
		AuthorizationDetails: []openid4vci.AuthorizationDetailsParameter{},
	}

	//dpop, err := oauth2.ValidateAndParseDPoPJWT(req.DPOP)
	//if err != nil {
	//	c.log.Error(err, "dpop validation error")
	//	return nil, err
	//}

	//if dpop.HTU != "https://vc-interop-3.sunet.se/token" {
	//	return nil, fmt.Errorf("invalid HTU in DPoP claims: %s", dpop.HTU)
	//}
	//if dpop.HTM != "POST" {
	//	return nil, fmt.Errorf("invalid HTM in DPoP claims: %s", dpop.HTM)
	//}

	//c.log.Debug("DPoP claims", "jti", dpop.JTI, "htu", dpop.HTU, "htm", dpop.HTM)

	// base64(sha256(code_verifier)) == stored code_challenge

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
