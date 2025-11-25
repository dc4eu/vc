package apiv1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"vc/pkg/model"
	"vc/pkg/openid4vp"
	"vc/pkg/sdjwtvc"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

type VerificationRequestObjectRequest struct {
	ID string `form:"id" uri:"id"`
	//SessionID string `json:"-"`
}

func (c *Client) VerificationRequestObject(ctx context.Context, req *VerificationRequestObjectRequest) (string, error) {
	c.log.Debug("Verification request object", "req", req)

	// TODO(masv): should request-object-id be associated with a particular session?
	authorizationContext, err := c.db.AuthorizationContextColl.Get(ctx, &model.AuthorizationContext{
		RequestObjectID: req.ID,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return "", err
	}

	requestObject, found := c.openid4vp.RequestObjectCache.Get(authorizationContext.RequestObjectID)
	if !found {
		c.log.Error(nil, "request object not found in cache", "requestObjectID", authorizationContext.RequestObjectID)
		return "", errors.New("request object not found")
	}

	signedJWT, err := requestObject.Sign(jwt.SigningMethodRS256, c.issuerMetadataSigningKey, c.issuerMetadataSigningChain)
	if err != nil {
		c.log.Error(err, "failed to sign authorization request")
		return "", err
	}

	c.log.Debug("Signed JWT", "jwt", signedJWT)

	return signedJWT, nil
}

type VerificationDirectPostRequest struct {
	Response string `json:"response"  form:"response"`
}

func (v *VerificationDirectPostRequest) GetKID() (string, error) {
	fmt.Println("Kid")
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
	RedirectURI string `json:"redirect_uri"`
}

func (c *Client) VerificationDirectPost(ctx context.Context, req *VerificationDirectPostRequest) (*VerificationDirectPostResponse, error) {
	c.log.Debug("Verification direct-post")

	// Extract KID from JWE header
	kid, err := req.GetKID()
	if err != nil {
		c.log.Error(err, "failed to get KID from request")
		return nil, err
	}

	// Get ephemeral private key from cache
	privateEphemeralJWK, found := c.openid4vp.EphemeralKeyCache.Get(kid)
	if !found {
		c.log.Debug("No ephemeral key found in cache", "kid", kid)
		return nil, errors.New("ephemeral key not found in cache")
	}

	c.log.Debug("Found ephemeral key in cache", "kid", kid)

	// Decrypt JWE response
	decryptedJWE, err := jwe.Decrypt([]byte(req.Response), jwe.WithKey(jwa.ECDH_ES(), privateEphemeralJWK))
	if err != nil {
		c.log.Error(err, "failed to decrypt JWE")
		return nil, err
	}

	// Parse response parameters using openid4vp
	vpResponse := openid4vp.VPResponse{}
	if err := json.Unmarshal(decryptedJWE, &vpResponse); err != nil {
		c.log.Error(err, "failed to unmarshal decrypted JWE")
		return nil, err
	}

	responseParams := &openid4vp.ResponseParameters{}
	responseParams.State = vpResponse.State

	// Get authorization context by state
	authCtx, err := c.db.AuthorizationContextColl.Get(ctx, &model.AuthorizationContext{State: responseParams.State})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return nil, err
	}

	responseParams.VPToken = vpResponse.VPToken[authCtx.Scope]

	// Validate response parameters
	if err := responseParams.Validate(); err != nil {
		c.log.Error(err, "response parameters validation failed")
		return nil, fmt.Errorf("invalid response: %w", err)
	}

	// Validate VP Token using VPTokenValidator
	validator := &openid4vp.VPTokenValidator{
		Nonce:           authCtx.Nonce,
		ClientID:        authCtx.ClientID,
		VerifySignature: true,
		CheckRevocation: false,
	}

	if err := validator.Validate(responseParams.VPToken); err != nil {
		c.log.Error(err, "VP Token validation failed")
		return nil, fmt.Errorf("VP Token validation failed: %w", err)
	}

	c.log.Debug("VP Token validated successfully")

	// Parse SD-JWT credential
	header, body, signature, selectiveDisclosure, keyBinding, err := sdjwtvc.Token(responseParams.VPToken).Split()
	if err != nil {
		c.log.Error(err, "failed to split sd-jwt")
		return nil, err
	}

	c.log.Debug("SD-JWT parts", "header", header)
	c.log.Debug("SD-JWT parts", "body", body)
	c.log.Debug("SD-JWT parts", "signature", signature)
	c.log.Debug("SD-JWT parts", "selectiveDisclosure", selectiveDisclosure)
	c.log.Debug("SD-JWT parts", "keyBinding", keyBinding)

	// Parse credential claims
	parsed, err := sdjwtvc.Token(responseParams.VPToken).Parse()
	if err != nil {
		c.log.Error(err, "failed to parse sd-jwt credential")
		return nil, err
	}

	// Generate response code
	responseCode := uuid.NewString()

	// Cache validated credential
	c.credentialCache.Set(responseCode, []sdjwtvc.CredentialCache{
		{
			Credential: parsed.Claims,
			Claims:     nil,
		},
	}, ttlcache.DefaultTTL)

	c.log.Debug("Credential cached", "response_code", responseCode)

	reply := &VerificationDirectPostResponse{
		RedirectURI: fmt.Sprintf(c.cfg.Verifier.ExternalServerURL+"/verification/callback?response_code=%s", responseCode),
	}

	return reply, nil
}

type VerificationCallbackRequest struct {
	ResponseCode string `form:"response_code" uri:"response_code"`
}

type VerificationCallbackResponse struct {
	CredentialData []sdjwtvc.CredentialCache `json:"credential_data"`
}

func (c *Client) VerificationCallback(ctx context.Context, req *VerificationCallbackRequest) (*VerificationCallbackResponse, error) {
	c.log.Debug("verificationCallback", "req", req)

	if has := c.credentialCache.Has(req.ResponseCode); !has {
		return nil, fmt.Errorf("no item in crededential cache matching id %s", req.ResponseCode)
	}

	credential := c.credentialCache.Get(req.ResponseCode).Value()

	reply := &VerificationCallbackResponse{
		CredentialData: credential,
	}

	return reply, nil
}
