package apiv1

import (
	"context"
	"vc/pkg/datastoreclient"
	"vc/pkg/openid4vci"
)

// CredentialOfferRequest for wallet to use the credential offer
type CredentialOfferRequest struct {
	CredentialOffer     openid4vci.CredentialOffer `json:"credential_offer" validate:"required"`
	ClientID            string                     `json:"client_id" validate:"required"`
	RedirectURI         string                     `json:"redirect_uri" validate:"required"`
	CodeChallenge       string                     `json:"code_challenge" validate:"required"`
	CodeChallengeMethod string                     `json:"code_challenge_method" validate:"required"`
	State               string                     `json:"state"`
}

// CredentialOffer handler the request to issuer with the credential offer
func (c *Client) CredentialOffer(ctx context.Context, req *CredentialOfferRequest) error {
	c.log.Debug("credential offer")

	apigwClient, err := datastoreclient.New(&datastoreclient.Config{URL: "http://vc_dev_apigw:8080"})
	if err != nil {
		return err
	}

	// issuer metadata

	issuerMetadata, _, err := apigwClient.OIDC.IssuerMetadata(ctx)
	if err != nil {
		return err
	}
	c.log.Debug("issuer metadata", "issuerMetadata", issuerMetadata)
	// credential offer

	// unpack credential offer
	co, err := req.CredentialOffer.Unpack(ctx)
	if err != nil {
		return err
	}
	//	c.log.Debug("credential offer unpacked", "co", co)

	var issuingState string
	grant, ok := co.Grants["authorization_code"]
	if ok {
		issuingState = grant.(*openid4vci.GrantAuthorizationCode).IssuerState
	}

	//c.log.Debug("issuing state", "issuingState", issuingState)

	// authentication
	authRequest := &openid4vci.AuthorizationRequest{
		ResponseType:         "code",
		ClientID:             req.ClientID,
		RedirectURI:          req.RedirectURI,
		Scope:                "",
		State:                req.State,
		AuthorizationDetails: []openid4vci.AuthorizationDetailsParameter{},
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		WalletIssuer:         "",
		UserHint:             "",
		IssuingState:         issuingState,
	}

	//authorizeResponse, httpResponse, err := apigwClient.OIDC.Par(ctx, authRequest)

	authorizeResponse, httpResponse, err := apigwClient.OIDC.Authorize(ctx, authRequest)
	if err != nil {
		c.log.Error(err, "authorize error", "httpResponse", httpResponse)
		return err
	}

	// token
	// credential
	c.log.Debug("authorize response", "httpResponse", httpResponse)

	c.log.Debug("authorize response", "authorizeResponse", authorizeResponse)

	return nil
}
