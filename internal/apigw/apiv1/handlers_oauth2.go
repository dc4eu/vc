package apiv1

import (
	"context"
	"time"
	"vc/pkg/model"
	"vc/pkg/openid4vci"

	"github.com/google/uuid"
)

// OIDCAuth  https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-endpoint
func (c *Client) OIDCAuth(ctx context.Context, req *openid4vci.AuthorizationRequest) (string, error) {
	response := &openid4vci.AuthorizationResponse{
		Code:  uuid.NewString(),
		State: req.State,
	}

	c.log.Debug("OIDCAuth")

	granted, err := c.db.VCUsersColl.Grant(ctx, req.ClientID)
	if err != nil {
		c.log.Debug("grant error", "err", err)
		return "", err
	}
	if !granted {
		c.log.Debug("grant denied")
		return "", &openid4vci.Error{Err: openid4vci.ErrUnauthorizedClient, ErrorDescription: "client_id not found"}
	}

	azt := model.Authorization{
		Code:     response.Code,
		IsUsed:   false,
		State:    response.State,
		ExpireAt: time.Now().Add(9 * time.Minute).Unix(),
		ClientID: req.ClientID,
	}

	if err := c.db.VCAuthColl.Save(ctx, &azt); err != nil {
		c.log.Error(err, "save error")
		return "", err
	}

	c.log.Debug("save success")

	redirectURL, err := response.AuthRedirectURL(req.RedirectURI)
	if err != nil {
		c.log.Error(err, "redirect error")
		return "", err
	}

	return redirectURL, nil
}

// OIDCToken https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-token-endpoint
func (c *Client) OIDCToken(ctx context.Context, req *openid4vci.TokenRequest) (*openid4vci.TokenResponse, error) {
	// base64(sha256(code_verifier)) == stored code_challenge

	//c.db.VCAuthColl.Grant(ctx, req.ClientID, req.Code)

	// Check if ClientID and Code match
	// Check if Code have been used
	// Check if Code is expired
	return nil, nil
}
