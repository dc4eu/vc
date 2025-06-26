package apiv1

import (
	"context"
	"encoding/json"
	"time"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vp"

	"github.com/golang-jwt/jwt/v5"
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

	pd := openid4vp.PresentationDefinitionParameter{}
	if err := json.Unmarshal(presentationDefinition, &pd); err != nil {
		return "", err
	}

	vf := map[string]map[string][]string{}
	if err := json.Unmarshal(vpFormats, &vf); err != nil {
		return "", err
	}

	nonce, err := oauth2.GenerateCryptographicNonce(32)
	if err != nil {
		return "", err
	}


	authorizationRequest := openid4vp.AuthorizationRequest_v2{
		ResponseURI:            "https://vc-interop-3.sunet.se/verification/direct_post",
		AUD:                    "https://self-issued.me/v2",
		ISS:                    "1003",
		ClientIDScheme:         "x509_san_dns",
		ClientID:               "1003",
		ResponseType:           "vp_token",
		ResponseMode:           "direct_post.jwt",
		State:                  req.ID,
		Nonce:                  nonce, // should come from token
		PresentationDefinition: &pd,
		ClientMetadata: &openid4vp.ClientMetadata{
			JWKS:                              openid4vp.Keys{},
			VPFormats:                         vf,
			AuthorizationEncryptedResponseALG: "ECDH-ES",
			AuthorizationEncryptedResponseENC: "A256GCM",
		},
		IAT: time.Now().UTC().Unix(),
	}

	signedJWT, err := authorizationRequest.Sign(jwt.SigningMethodRS256, c.issuerMetadataSigningKey, c.issuerMetadataSigningChain)
	if err != nil {
		c.log.Error(err, "failed to sign authorization request")
		return "", err
	}

	c.log.Debug("Signed JWT", "jwt", signedJWT)

	return signedJWT, nil
}

type VerificationDirectPostRequest struct {
}

type VerificationDirectPostResponse struct{}

func (c *Client) VerificationDirectPost(ctx context.Context, req *VerificationDirectPostRequest) (*VerificationDirectPostResponse, error) {
	c.log.Debug("Verification direct-post", "req", req)

	return nil, nil
}
