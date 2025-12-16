package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"vc/internal/apigw/db"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/gen/registry/apiv1_registry"
	"vc/pkg/helpers"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCCredentialOffer https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
func (c *Client) OIDCCredentialOffer(ctx context.Context, req *openid4vci.CredentialOfferParameters) (*openid4vci.CredentialOfferParameters, error) {
	c.log.Debug("credential offer")
	return nil, nil
}

// OIDCNonce https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-endpoint
func (c *Client) OIDCNonce(ctx context.Context) (*openid4vci.NonceResponse, error) {
	nonce, err := openid4vci.GenerateNonce(0)
	if err != nil {
		return nil, err
	}
	response := &openid4vci.NonceResponse{
		CNonce: nonce,
	}
	return response, nil
}

// OIDCCredential makes a credential
//
//	@Summary		OIDCCredential
//	@ID				create-credential
//	@Description	Create credential endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	apiv1_issuer.MakeSDJWTReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse			"Bad Request"
//	@Param			req	body		openid4vci.CredentialRequest	true	" "
//	@Router			/credential [post]
func (c *Client) OIDCCredential(ctx context.Context, req *openid4vci.CredentialRequest) (*openid4vci.CredentialResponse, error) {
	dpop, err := oauth2.ValidateAndParseDPoPJWT(req.DPoP)
	if err != nil {
		c.log.Error(err, "failed to validate DPoP JWT")
		return nil, err
	}

	requestATH := req.HashAuthorizeToken()

	if !dpop.IsAccessTokenDPoP(requestATH) {
		return nil, errors.New("invalid DPoP token")
	}

	accessToken := strings.TrimPrefix(req.Authorization, "DPoP ")

	authContext, err := c.authContextStore.GetWithAccessToken(ctx, accessToken)
	if err != nil {
		c.log.Error(err, "failed to get authorization")
		return nil, err
	}

	if len(authContext.Scope) == 0 {
		c.log.Error(nil, "no scope found in auth context")
		return nil, errors.New("no scope found in auth context")
	}

	document := &model.CompleteDocument{}

	// TODO(masv): make this flexible, use config.yaml credential constructor
	switch authContext.Scope[0] {
	case "ehic", "pda1", "diploma":
		docs := c.documentCache.Get(authContext.SessionID).Value()
		if docs == nil {
			c.log.Error(nil, "no documents found in cache for session", "session_id", authContext.SessionID)
			return nil, errors.New("no documents found for session " + authContext.SessionID)
		}
		for _, doc := range docs {
			document = doc
			break
		}

	case "pid_1_5":
		document, err = c.datastoreStore.GetDocumentWithIdentity(ctx, &db.GetDocumentQuery{
			Meta: &model.MetaData{
				AuthenticSource: authContext.AuthenticSource,
				VCT:             model.CredentialTypeUrnEudiPidARF151,
			},
			Identity: authContext.Identity,
		})
		if err != nil {
			return nil, err
		}

	case "pid_1_8":
		document, err = c.datastoreStore.GetDocumentWithIdentity(ctx, &db.GetDocumentQuery{
			Meta: &model.MetaData{
				AuthenticSource: authContext.AuthenticSource,
				VCT:             model.CredentialTypeUrnEudiPidARG181,
			},
			Identity: authContext.Identity,
		})
		if err != nil {
			return nil, err
		}

	default:
		c.log.Error(nil, "unsupported scope", "scope", authContext.Scope)
		return nil, errors.New("unsupported scope")
	}

	documentData, err := json.Marshal(document.DocumentData)
	if err != nil {
		return nil, err
	}

	// Extract JWK from proof (singular) or proofs (plural/batch)
	var jwk *apiv1_issuer.Jwk
	if req.Proof != nil {
		jwk, err = req.Proof.ExtractJWK()
		if err != nil {
			c.log.Error(err, "failed to extract JWK from proof")
			return nil, err
		}
	} else if req.Proofs != nil {
		jwk, err = req.Proofs.ExtractJWK()
		if err != nil {
			c.log.Error(err, "failed to extract JWK from proofs")
			return nil, err
		}
	} else {
		return nil, errors.New("no proof found in credential request")
	}

	reply, err := c.issuerClient.MakeSDJWT(ctx, &apiv1_issuer.MakeSDJWTRequest{
		Scope:        authContext.Scope[0],
		DocumentData: documentData,
		Jwk:          jwk,
	})
	if err != nil {
		c.log.Error(err, "failed to call MakeSDJWT")
		return nil, err
	}

	if reply == nil {
		return nil, errors.New("MakeSDJWT reply is nil")
	}

	// Save credential subject info to registry for status management
	if len(document.Identities) > 0 {
		identity := document.Identities[0]
		_, err = c.registryClient.SaveCredentialSubject(ctx, &apiv1_registry.SaveCredentialSubjectRequest{
			FirstName:   identity.GivenName,
			LastName:    identity.FamilyName,
			DateOfBirth: identity.BirthDate,
			Section:     reply.TokenStatusListSection,
			Index:       reply.TokenStatusListIndex,
		})
		if err != nil {
			c.log.Error(err, "failed to save credential subject to registry")
		}
	}

	response := &openid4vci.CredentialResponse{}
	switch len(reply.Credentials) {
	case 0:
		return nil, helpers.ErrNoDocumentFound
	case 1:
		response.Credentials = []openid4vci.Credential{
			{
				Credential: reply.Credentials[0].Credential,
			},
		}
		return response, nil
	default:
		return nil, errors.New("multiple credentials returned from issuer, not supported")
	}
}

// OIDCDeferredCredential https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoin
func (c *Client) OIDCDeferredCredential(ctx context.Context, req *openid4vci.DeferredCredentialRequest) (*openid4vci.CredentialResponse, error) {
	c.log.Debug("deferred credential", "req", req)
	// run the same code as OIDCCredential
	return nil, nil
}

// OIDCredentialOfferURI https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-14.html#name-sending-credential-offer-by-
func (c *Client) OIDCredentialOfferURI(ctx context.Context, req *openid4vci.CredentialOfferURIRequest) (*openid4vci.CredentialOfferParameters, error) {
	c.log.Debug("credential offer uri", "req", req.CredentialOfferUUID)
	doc, err := c.credentialOfferStore.Get(ctx, req.CredentialOfferUUID)
	if err != nil {
		c.log.Debug("failed to marshal document data", "error", err)
		return nil, err
	}

	return &doc.CredentialOfferParameters, nil
}

// OIDCNotification https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-endpoint
func (c *Client) OIDCNotification(ctx context.Context, req *openid4vci.NotificationRequest) error {
	c.log.Debug("notification", "req", req)
	return nil
}

// OIDCMetadata https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-issuer-metadata-
func (c *Client) OIDCMetadata(ctx context.Context) (*openid4vci.CredentialIssuerMetadataParameters, error) {
	c.log.Debug("metadata request")

	signedMetadata, err := c.issuerMetadata.Sign(jwt.SigningMethodRS256, c.issuerMetadataSigningKey, c.issuerMetadataSigningChain)
	if err != nil {
		return nil, err
	}
	if err := helpers.Check(ctx, c.cfg, signedMetadata, c.log); err != nil {
		c.log.Error(err, "failed to check metadata")
		return nil, err
	}

	return signedMetadata, nil
}
