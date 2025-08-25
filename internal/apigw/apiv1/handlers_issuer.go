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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
//	@Success		200	{object}	apiv1_issuer.MakeSDJWTReply	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse		"Bad Request"
//	@Param			req	body		openid4vci.CredentialRequest			true	" "
//	@Router			/credential [post]
func (c *Client) OIDCCredential(ctx context.Context, req *openid4vci.CredentialRequest) (*openid4vci.CredentialResponse, error) {
	c.log.Debug("credential", "req", req.Proof.ProofType)

	dpop, err := oauth2.ValidateAndParseDPoPJWT(req.Headers.DPoP)
	if err != nil {
		c.log.Error(err, "failed to validate DPoP JWT")
		return nil, err
	}

	jti := dpop.JTI

	sig := strings.Split(req.Headers.DPoP, ".")[2]
	c.log.Debug("DPoP JWT", "jti", jti, "sig", sig, "dpop JWK", sig)
	c.log.Debug("Credential request header", "authorization", req.Headers.Authorization, "dpop", req.Headers.DPoP)

	requestATH := req.Headers.HashAuthorizeToken()

	if !dpop.IsAccessTokenDPoP(requestATH) {
		return nil, errors.New("invalid DPoP token")
	}

	// "DPoP H4fFxp2hDZ-KY-_am35sXBJStQn9plmV_UC_bk20heA="
	accessToken := strings.TrimPrefix(req.Headers.Authorization, "DPoP ")

	c.log.Debug("DPoP token is valid", "dpop", dpop, "requestATH", requestATH, "accessToken", accessToken)

	authContext, err := c.db.VCAuthorizationContextColl.GetWithAccessToken(ctx, accessToken)
	if err != nil {
		c.log.Error(err, "failed to get authorization")
		return nil, err
	}

	c.log.Debug("credential", "authContext", authContext)

	document := &model.CompleteDocument{}

	switch authContext.Scope {
	case "ehic", "pda1", "diploma":
		c.log.Debug("ehic/pda1/diploma scope detected")
		docs := c.documentCache.Get(authContext.SessionID).Value()
		if docs == nil {
			c.log.Error(nil, "no documents found in cache for session", "session_id", authContext.SessionID)
			return nil, errors.New("no documents found for session " + authContext.SessionID)
		}
		for _, doc := range docs {
			document = &doc
		}

	case "pid":
		c.log.Debug("pid scope detected")
		document, err = c.db.VCDatastoreColl.GetDocumentWithIdentity(ctx, &db.GetDocumentQuery{
			Meta: &model.MetaData{
				AuthenticSource: authContext.AuthenticSource,
				DocumentType:    authContext.DocumentType,
			},
			Identity: authContext.Identity,
		})
		if err != nil {
			c.log.Debug("failed to get document", "error", err)
			return nil, err
		}

	default:
		c.log.Error(nil, "unsupported scope", "scope", authContext.Scope)
	}

	documentData, err := json.Marshal(document.DocumentData)
	if err != nil {
		c.log.Debug("failed to marshal document data", "error", err)
		return nil, err
	}
	c.log.Debug("Here 0", "documentData", string(documentData))

	jwk, err := req.Proof.ExtractJWK()
	if err != nil {
		c.log.Error(err, "failed to extract JWK from proof")
		return nil, err
	}

	c.log.Debug("Here 1", "jwk", jwk)
	c.log.Debug("MakeSDJWT request", "documentType", document.Meta.DocumentType)

	//	// Build SDJWT
	conn, err := grpc.NewClient(c.cfg.Issuer.GRPCServer.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.log.Error(err, "Failed to connect to issuer")
		return nil, err
	}
	defer conn.Close()
	client := apiv1_issuer.NewIssuerServiceClient(conn)

	reply, err := client.MakeSDJWT(ctx, &apiv1_issuer.MakeSDJWTRequest{
		DocumentType: document.Meta.DocumentType,
		DocumentData: documentData,
		Jwk:          jwk,
	})
	if err != nil {
		c.log.Error(err, "failed to call MakeSDJWT")
		return nil, err
	}

	c.log.Debug("MakeSDJWT reply", "reply", reply)

	if reply == nil {
		c.log.Debug("MakeSDJWT reply is nil")
		return nil, errors.New("MakeSDJWT reply is nil")
	}

	c.log.Debug("Here 2")

	response := &openid4vci.CredentialResponse{}
	switch len(reply.Credentials) {
	case 0:
		c.log.Debug("No credentials returned from issuer")
		return nil, helpers.ErrNoDocumentFound
	case 1:
		c.log.Debug("Single credential returned from issuer")
		response.Credential = reply.Credentials[0].Credential
		return response, nil
	default:
		c.log.Debug("Multiple credentials returned from issuer")
		//response.Credentials = reply.Credentials
		return nil, errors.New("multiple credentials returned from issuer, not supported")
	}

	//return response, nil
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
	doc, err := c.db.VCCredentialOfferColl.Get(ctx, req.CredentialOfferUUID)
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

// RevokeRequest is the request for GenericRevoke
type RevokeRequest struct {
	AuthenticSource string `json:"authentic_source"`
	DocumentType    string `json:"document_type"`
	DocumentID      string `json:"document_id"`
	RevocationID    string `json:"revocation_id"`
}

// RevokeReply is the reply for GenericRevoke
type RevokeReply struct {
	Data struct {
		Status bool `json:"status"`
	}
}

// Revoke revokes a document
//
//	@Summary		Revoke
//	@ID				generic-revoke
//	@Description	Revoke endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	RevokeReply				"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		RevokeRequest			true	" "
//	@Router			/revoke [post]
func (c *Client) Revoke(ctx context.Context, req *RevokeRequest) (*RevokeReply, error) {
	optInsecure := grpc.WithTransportCredentials(insecure.NewCredentials())

	conn, err := grpc.NewClient(c.cfg.Registry.GRPCServer.Addr, optInsecure)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := apiv1_registry.NewRegistryServiceClient(conn)
	resp, err := client.Revoke(ctx, &apiv1_registry.RevokeRequest{
		Entity: "mura",
	})
	if err != nil {
		return nil, err
	}

	reply := &RevokeReply{
		Data: struct {
			Status bool `json:"status"`
		}{
			Status: resp.Status,
		},
	}
	return reply, nil
}
