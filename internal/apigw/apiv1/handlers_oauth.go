package apiv1

import (
	"context"
	"errors"
	"fmt"
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
		return nil, errors.New("invalid client")
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
	authorization, err := c.db.VCAuthzColl.Get(ctx, req.RequestURI)
	if err != nil {
		c.log.Error(err, "get error")
		return nil, err
	}

	c.log.Debug("Authorize", "authorization", authorization)

	response := &openid4vci.AuthorizationResponse{
		Code:  authorization.Code,
		State: authorization.State,
	}

	return response, nil
}

// OIDCToken https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-token-endpoint
func (c *Client) OAuthToken(ctx context.Context, req *openid4vci.TokenRequest) (*openid4vci.TokenResponse, error) {
	c.log.Debug("OIDCToken")
	c.log.Debug("req", "data", req)

	// base64(sha256(code_verifier)) == stored code_challenge

	//c.db.VCAuthColl.Grant(ctx, req.ClientID, req.Code)

	// Check if ClientID and Code match
	// Check if Code have been used
	// Check if Code is expired
	return nil, nil
}

func (c *Client) OAuthMetadata(ctx context.Context) (*oauth2.AuthorizationServerMetadata, error) {
	c.log.Debug("metadata request")

	signedMetadata, err := c.oauth2Metadata.Sign(jwt.SigningMethodRS256, c.oauth2MetadataSigningKey, c.oauth2MetadataSigningChain)
	if err != nil {
		return nil, err
	}

	return signedMetadata, nil

}
