package apiv1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"vc/internal/apigw/db"
	"vc/pkg/model"
	"vc/pkg/openid4vp"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

var vpFormats = []byte(
	`{
      "vc+sd-jwt": {
        "sd-jwt_alg_values": [
          "ES256"
        ],
        "kb-jwt_alg_values": [
          "ES256"
        ]
      },
      "dc+sd-jwt": {
        "sd-jwt_alg_values": [
          "ES256"
        ],
        "kb-jwt_alg_values": [
          "ES256"
        ]
      },
      "mso_mdoc": {
        "alg": [
          "ES256"
        ]
      }
    }
`)

type VerificationRequestObjectRequest struct {
	ID string `form:"id" uri:"id"`
}

func (c *Client) VerificationRequestObject(ctx context.Context, req *VerificationRequestObjectRequest) (string, error) {
	c.log.Debug("Verification request object", "req", req)

	authorizationContext, err := c.db.VCAuthorizationContextColl.Get(ctx, &model.AuthorizationContext{
		VerifierResponseCode: req.ID,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return "", err
	}

	vf := map[string]map[string][]string{}
	if err := json.Unmarshal(vpFormats, &vf); err != nil {
		return "", err
	}

	_, ephemeralPublicJWK, err := c.EphemeralEncryptionKey(authorizationContext.EphemeralEncryptionKeyID)
	if err != nil {
		return "", err
	}

	authorizationRequest := openid4vp.RequestObject{
		ResponseURI:  "https://vc-interop-3.sunet.se/verification/direct_post",
		AUD:          "https://self-issued.me/v2",
		ISS:          authorizationContext.ClientID,
		ClientID:     authorizationContext.ClientID,
		ResponseType: "vp_token",
		ResponseMode: "direct_post.jwt",
		State:        authorizationContext.State,
		Nonce:        authorizationContext.Nonce,
		ClientMetadata: &openid4vp.ClientMetadata{
			VPFormats: vf,
			JWKS: &openid4vp.Keys{
				Keys: []jwk.Key{ephemeralPublicJWK},
			},
			AuthorizationEncryptedResponseALG: "ECDH-ES",
			AuthorizationEncryptedResponseENC: "A256GCM",
		},
		IAT: time.Now().UTC().Unix(),
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

type VerificationDirectPostRequest struct {
	Response string `json:"response" form:"response"`
}

func (v *VerificationDirectPostRequest) GetKID() (string, error) {
	header := strings.Split(v.Response, ".")[0]
	b, err := base64.RawStdEncoding.DecodeString(header)
	if err != nil {
		return "", err
	}

	var headerMap map[string]any
	if err := json.Unmarshal(b, &headerMap); err != nil {
		return "", err
	}

	kid, ok := headerMap["kid"]
	if !ok {
		return "", errors.New("kid not found in JWT header")
	}

	kidStr, ok := kid.(string)
	if !ok {
		return "", errors.New("kid is not a string")
	}

	return kidStr, nil
}

type VerificationDirectPostResponse struct {
	PresentationDuringIssuanceSession string `json:"presentation_during_issuance_session"`
	RedirectURI                       string `json:"redirect_uri"`
}

func (c *Client) VerificationDirectPost(ctx context.Context, req *VerificationDirectPostRequest) (*VerificationDirectPostResponse, error) {
	c.log.Debug("Verification direct-post")

	kid, err := req.GetKID()
	if err != nil {
		c.log.Error(err, "failed to get KID from request")
		return nil, err
	}

	privateEphemeralJWK := c.ephemeralEncryptionKeyCache.Get(kid).Value()
	if privateEphemeralJWK == nil {
		c.log.Debug("No ephemeral key found in cache", "kid", kid)
		return nil, errors.New("ephemeral key not found in cache")
	}

	c.log.Debug("Found ephemeral key in cache", "kid", kid)

	decryptedJWE, err := jwe.Decrypt([]byte(req.Response), jwe.WithKey(jwa.ECDH_ES(), privateEphemeralJWK))
	if err != nil {
		c.log.Error(err, "failed to decrypt JWE")
		return nil, err
	}

	authorizationContext, err := c.db.VCAuthorizationContextColl.Get(ctx, &model.AuthorizationContext{EphemeralEncryptionKeyID: kid})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return nil, err
	}

	responseParameters := &openid4vp.ResponseParameters{}
	if err := json.Unmarshal(decryptedJWE, &responseParameters); err != nil {
		c.log.Error(err, "failed to unmarshal decrypted JWE")
		return nil, err
	}

	credential, err := responseParameters.BuildCredential()
	if err != nil {
		c.log.Error(err, "failed to build credential from response parameters")
		return nil, err
	}

	credentialConstructorCfg, ok := c.cfg.CredentialConstructor[authorizationContext.Scope]
	if !ok {
		c.log.Error(nil, "credential constructor not found for scope", "scope", authorizationContext.Scope)
		return nil, errors.New("credential constructor not found for scope: " + authorizationContext.Scope)
	}

	identity := &model.Identity{
		GivenName:  credential["given_name"].(string),
		FamilyName: credential["family_name"].(string),
		BirthDate:  credential["birthdate"].(string),
	}

	documents, err := c.db.VCDatastoreColl.GetDocumentsWithIdentity(ctx, &db.GetDocumentQuery{
		Meta: &model.MetaData{
			DocumentType: credentialConstructorCfg.VCT,
		},
		Identity: identity,
	})
	if err != nil {
		c.log.Debug("failed to get document", "error", err)
		return nil, err
	}

	c.documentCache.Set(authorizationContext.SessionID, documents, ttlcache.DefaultTTL)

	reply := &VerificationDirectPostResponse{
		//ResponseCode: responseCode,
		RedirectURI: "https://vc-interop-3.sunet.se/authorization/consent/callback/?response_code=" + authorizationContext.VerifierResponseCode,
	}
	return reply, nil
}
