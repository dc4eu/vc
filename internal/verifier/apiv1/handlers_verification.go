package apiv1

import (
	"context"
	"fmt"
	"time"
	"vc/pkg/model"
	"vc/pkg/openid4vp"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type VerificationRequestObjectRequest struct {
	ID        string `form:"id" uri:"id"`
	SessionID string `json:"-"`
}

func (c *Client) VerificationRequestObject(ctx context.Context, req *VerificationRequestObjectRequest) (string, error) {
	c.log.Debug("Verification request object", "req", req)

	// TODO(masv): should request-object-id be associated with a particular session?
	authorizationContext, err := c.db.AuthorizationContextColl.Get(ctx, &model.AuthorizationContext{
		RequestObjectID: req.ID,
		SessionID:       req.SessionID,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return "", err
	}

	_, ephemeralPublicJWK, err := c.EphemeralEncryptionKey(authorizationContext.EphemeralEncryptionKeyID)
	if err != nil {
		return "", err
	}

	authorizationRequest := openid4vp.RequestObject{
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
		DCQLQuery:        authorizationContext.DCQLQuery,
		RequestURIMethod: "",
		TransactionData:  []openid4vp.TransactionData{},
		VerifierInfo:     []openid4vp.VerifierInfo{},
	}

	c.log.Debug("Authorization request", "request", authorizationRequest)

	signedJWT, err := authorizationRequest.Sign(jwt.SigningMethodRS256, c.issuerMetadataSigningKey, c.issuerMetadataSigningChain)
	if err != nil {
		c.log.Error(err, "failed to sign authorization request")
		return "", err
	}

	c.log.Debug("Signed JWT", "jwt", signedJWT)

	return signedJWT, nil
}
