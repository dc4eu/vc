package apiv1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"vc/pkg/model"
	"vc/pkg/openid4vp"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

var presentationDefinition = []byte(
	`{
    "id": "CustomVerifiableId",
    "title": "PID ARF v1.8",
    "description": "Select the format and the fields you want to request",
    "input_descriptors": [
      {
        "id": "SdJwtPID",
        "name": "Custom PID",
        "constraints": {
          "limit_disclosure": "required",
          "fields": [
            {
              "name": "VC type",
              "path": [
                "$.vct"
              ],
              "filter": {
                "type": "string",
                "const": "urn:eudi:pid:1"
              }
            },
            {
              "name": "First name",
              "path": [
                "$.given_name"
              ],
              "filter": {}
            },
             {
              "name": "Family name",
              "path": [
                "$.family_name"
              ],
              "filter": {}
            },
            {
              "name": "Birth date",
              "path": [
                "$.birthdate"
              ],
              "filter": {}
            }
          ]
        },
        "format": {
          "vc+sd-jwt": {
            "sd-jwt_alg_values": [
              "ES256"
            ],
            "kb-jwt_alg_values": [
              "ES256"
            ]
          }
        }
      }
    ]
}
`)

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

type VerificationRequestObjectResponse struct{}

func (c *Client) VerificationRequestObject(ctx context.Context, req *VerificationRequestObjectRequest) (string, error) {
	c.log.Debug("Verification request object", "req", req)

	authorizationContext, err := c.db.VCAuthorizationContextColl.Get(ctx, &model.AuthorizationContext{
		VerifierResponseCode: req.ID,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return "", err
	}

	c.log.Debug("verification requerst object", "context", authorizationContext)

	pd := openid4vp.PresentationDefinitionParameter{}
	if err := json.Unmarshal(presentationDefinition, &pd); err != nil {
		return "", err
	}
	pd.Purpose = fmt.Sprintf("Present your credential(s) to get your %s", authorizationContext.Scope)

	vf := map[string]map[string][]string{}
	if err := json.Unmarshal(vpFormats, &vf); err != nil {
		return "", err
	}

	_, ephemeralPublicJWK, err := c.EphemeralEncryptionKey(authorizationContext.EphemeralEncryptionKeyID)
	if err != nil {
		return "", err
	}

	authorizationRequest := openid4vp.AuthorizationRequest_v2{
		ResponseURI:            "https://vc-interop-3.sunet.se/verification/direct_post",
		AUD:                    "https://self-issued.me/v2",
		ISS:                    authorizationContext.ClientID,
		ClientIDScheme:         "x509_san_dns",
		ClientID:               authorizationContext.ClientID,
		ResponseType:           "vp_token",
		ResponseMode:           "direct_post.jwt",
		State:                  authorizationContext.State,
		Nonce:                  authorizationContext.Nonce,
		PresentationDefinition: &pd,
		ClientMetadata: &openid4vp.ClientMetadata{
			VPFormats: vf,
			JWKS: openid4vp.Keys{
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
	//Identity                          model.Identity `json:"-"`
	//ResponseCode                      string         `json:"-"`
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

	//c.log.Debug("Decrypted JWE", "decryptedJWE", string(decryptedJWE))

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

	identity := &model.Identity{
		GivenName:  credential["given_name"].(string),
		FamilyName: credential["family_name"].(string),
		BirthDate:  credential["birthdate"].(string),
	}

	credentialConstructorCfg, ok := c.cfg.CredentialConstructor[authorizationContext.Scope]
	if !ok {
		c.log.Error(nil, "credential constructor not found for scope", "scope", authorizationContext.Scope)
		return nil, errors.New("credential constructor not found for scope: " + authorizationContext.Scope)
	}

	update := &model.AuthorizationContext{
		Identity:        identity,
		DocumentType:    credentialConstructorCfg.VCT,
		AuthenticSource: "EHIC:00001",
	}

	if err := c.db.VCAuthorizationContextColl.AddIdentity(ctx, &model.AuthorizationContext{EphemeralEncryptionKeyID: kid}, update); err != nil {
		c.log.Error(err, "failed to add identity to authorization context")
		return nil, err
	}

	reply := &VerificationDirectPostResponse{
		//ResponseCode: responseCode,
		RedirectURI: "https://vc-interop-3.sunet.se/authorization/consent/callback/?response_code=" + authorizationContext.VerifierResponseCode,
	}
	return reply, nil
}
