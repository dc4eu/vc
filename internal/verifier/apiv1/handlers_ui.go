package apiv1

import (
	"context"
	"fmt"
	"time"
	"vc/pkg/model"
	"vc/pkg/openid4vp"

	"github.com/google/uuid"
	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
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
	//SessionID string `json:"-"`
}

type UIInteractionReply struct {
	AuthorizationRequest string `json:"authorization_request"`
	QRCode               string `json:"qr_code"`
}

// UIInteraction handles front-end interactions, replying with an Authorization Request that contains a Request URI and DCQL query, the latter for UI to show.
func (c *Client) UIInteraction(ctx context.Context, req *UIInteractionRequest) (*UIInteractionReply, error) {
	c.log.Debug("uiInteraction", "dcql_query", req.DCQLQuery)

	nonce := uuid.NewString()
	state := uuid.NewString()
	requestObjectID := uuid.NewString()
	sessionID := uuid.NewString()

	authorizationContext := &model.AuthorizationContext{
		SessionID:                sessionID,
		Scope:                    req.DCQLQuery.Credentials[0].ID,
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

	_, ephemeralPublicJWK, err := c.EphemeralEncryptionKey(authorizationContext.EphemeralEncryptionKeyID)
	if err != nil {
		return nil, err
	}

	requestObject := &openid4vp.RequestObject{
		ResponseURI:  fmt.Sprintf("%s/verification/direct_post", c.cfg.Verifier.ExternalServerURL),
		AUD:          "https://self-issued.me/v2",
		ISS:          "vc-interop-3.sunet.se",
		ClientID:     authorizationContext.ClientID,
		ResponseType: "vp_token",
		ResponseMode: "direct_post.jwt",
		State:        authorizationContext.State,
		Nonce:        authorizationContext.Nonce,
		ClientMetadata: &openid4vp.ClientMetadata{
			VPFormats: map[string]map[string][]string{
				"vc+sd-jwt": {
					"sd-jwt_alg_values": {"ES256"},
					"kb-jwt_alg_values": {"ES256"}},
			},
			JWKS: &openid4vp.Keys{
				Keys: []jwk.Key{ephemeralPublicJWK},
			},
			AuthorizationSignedResponseALG:    "",
			AuthorizationEncryptedResponseALG: "ECDH-ES",
			AuthorizationEncryptedResponseENC: "A256GCM",
		},
		IAT:              time.Now().UTC().Unix(),
		RedirectURI:      "",
		Scope:            "",
		DCQLQuery:        req.DCQLQuery,
		RequestURIMethod: "",
		TransactionData:  []openid4vp.TransactionData{},
		VerifierInfo:     []openid4vp.VerifierInfo{},
	}

	if err := c.db.AuthorizationContextColl.Save(ctx, authorizationContext); err != nil {
		return nil, err
	}

	c.requestObjectCache.Set(authorizationContext.RequestObjectID, requestObject, ttlcache.DefaultTTL)

	reply := &UIInteractionReply{}

	reply.AuthorizationRequest, err = requestObject.CreateAuthorizationRequestURI(ctx, c.cfg.Verifier.ExternalServerURL, requestObjectID)
	if err != nil {
		return nil, err
	}

	reply.QRCode, err = openid4vp.GenerateQRV2(ctx, reply.AuthorizationRequest)
	if err != nil {
		return nil, err
	}

	return reply, nil
}
