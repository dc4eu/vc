package apiv1

import (
	"context"
	"vc/pkg/model"
	"vc/pkg/openid4vp"

	"github.com/google/uuid"
)

type UIMetadataReply struct {
	Credentials      map[string]*model.CredentialConstructor `json:"credentials"`
	SupportedWallets map[string]string                       `json:"supported_wallets"`
}

func (c *Client) UIMetadata(ctx context.Context) (*UIMetadataReply, error) {

	reply := &UIMetadataReply{}
	reply.Credentials = c.cfg.CredentialConstructor

	for _, constructor := range reply.Credentials {
		constructor.AuthMethod = ""
		constructor.VCTMFilePath = ""
		constructor.VCTM = nil
	}

	reply.SupportedWallets = c.cfg.Verifier.SupportedWallets

	return reply, nil
}

type UIInteractionRequest struct {
	DCQLQuery *openid4vp.DCQL `json:"dcql_query" validate:"required"`

	// SessionID from http server endpoint
	SessionID string `json:"-"`
}

type UIInteractionReply struct {
	AuthorizationRequest string `json:"authorization_request"`
	QRCode               string `json:"qr_code"`
}

// UIInteraction handles front-end interactions, replying with an Authorization Request that contains a Request URI and DCQL query, the latter for UI to show.
func (c *Client) UIInteraction(ctx context.Context, req *UIInteractionRequest) (*UIInteractionReply, error) {
	c.log.Debug("uIPresentationDefinition", "dcql_query", req.DCQLQuery)

	nonce := uuid.NewString()
	state := uuid.NewString()
	requestObjectID := uuid.NewString()

	authorizationContext := &model.AuthorizationContext{
		SessionID:                req.SessionID,
		Scope:                    "",
		Code:                     "",
		RequestURI:               "",
		WalletURI:                "",
		IsUsed:                   false,
		State:                    state,
		ClientID:                 "x509_san_dns:vc-interop-3.sunet.se",
		ExpiresAt:                0,
		CodeChallenge:            "",
		CodeChallengeMethod:      "",
		LastUsed:                 0,
		SavedAt:                  0,
		Consent:                  false,
		AuthenticSource:          "",
		DocumentType:             "",
		Identity:                 &model.Identity{},
		Token:                    &model.Token{},
		Nonce:                    nonce,
		EphemeralEncryptionKeyID: uuid.NewString(),
		VerifierResponseCode:     "",
		RequestObjectID:          requestObjectID,
	}

	authorizationObject := &openid4vp.RequestObject{
		ClientID: authorizationContext.ClientID,
	}

	if err := c.db.AuthorizationContextColl.Save(ctx, authorizationContext); err != nil {
		return nil, err
	}

	reply := &UIInteractionReply{}

	var err error
	reply.AuthorizationRequest, err = authorizationObject.CreateAuthorizationRequestURI(ctx, c.cfg.Verifier.ExternalServerURL, requestObjectID)
	if err != nil {
		return nil, err
	}

	reply.QRCode, err = openid4vp.GenerateQRV2(ctx, reply.AuthorizationRequest)
	if err != nil {
		return nil, err
	}

	return reply, nil
}
