//go:build oidcrp

package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	apiv1_issuer "vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/openid4vci"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// OIDCRPInitiateRequest represents the request to initiate OIDC authentication
type OIDCRPInitiateRequest struct {
	CredentialType string `json:"credential_type" binding:"required"`
}

// OIDCRPInitiateResponse represents the response with authorization URL
type OIDCRPInitiateResponse struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
}

// endpointOIDCRPInitiate initiates OIDC authentication flow
//
//	@Summary		Initiate OIDC Authentication
//	@Description	Initiates OIDC authentication by generating an OAuth2 authorization URL with PKCE
//	@Tags			OIDCRP
//	@Accept			json
//	@Produce		json
//	@Param			request	body		OIDCRPInitiateRequest	true	"OIDC RP initiate request"
//	@Success		200		{object}	OIDCRPInitiateResponse
//	@Failure		400		{object}	map[string]interface{}	"Bad request"
//	@Failure		500		{object}	map[string]interface{}	"Internal server error"
//	@Router			/oidcrp/initiate [post]
func (s *Service) endpointOIDCRPInitiate(ctx context.Context, c *gin.Context) (interface{}, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointOIDCRPInitiate")
	defer span.End()

	if s.oidcrpService == nil {
		span.SetStatus(codes.Error, "OIDC RP not configured")
		return nil, fmt.Errorf("OIDC RP is not enabled")
	}

	var req OIDCRPInitiateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	authReq, err := s.oidcrpService.InitiateAuth(ctx, req.CredentialType)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &OIDCRPInitiateResponse{
		AuthorizationURL: authReq.AuthorizationURL,
		State:            authReq.State,
	}, nil
}

// endpointOIDCRPCallback handles the OIDC Provider callback
// This is where the OIDC Provider redirects after authentication
//
//	@Summary		OIDC Provider Callback
//	@Description	Receives and processes the authorization code from the OIDC Provider
//	@Tags			OIDCRP
//	@Accept			application/x-www-form-urlencoded
//	@Produce		json
//	@Param			code	query		string					true	"Authorization code"
//	@Param			state	query		string					true	"OAuth2 state parameter"
//	@Success		200		{object}	map[string]interface{}	"Success with credential and offer"
//	@Failure		400		{object}	map[string]interface{}	"Bad request"
//	@Failure		500		{object}	map[string]interface{}	"Internal server error"
//	@Router			/oidcrp/callback [get]
func (s *Service) endpointOIDCRPCallback(ctx context.Context, c *gin.Context) (interface{}, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointOIDCRPCallback")
	defer span.End()

	if s.oidcrpService == nil {
		span.SetStatus(codes.Error, "OIDC RP not configured")
		return nil, fmt.Errorf("OIDC RP is not enabled")
	}

	// Extract query parameters
	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		span.SetStatus(codes.Error, "missing code or state parameter")
		return nil, fmt.Errorf("missing required parameters: code and state")
	}

	// Process the callback
	authResp, err := s.oidcrpService.ProcessCallback(ctx, code, state)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Retrieve session to get credential type
	session, err := s.oidcrpService.GetSession(state)
	if err != nil {
		span.SetStatus(codes.Error, "session retrieval failed")
		return nil, fmt.Errorf("failed to retrieve session: %w", err)
	}

	// Build transformer from config
	transformer, err := s.oidcrpService.BuildTransformer()
	if err != nil {
		span.SetStatus(codes.Error, "transformer creation failed")
		return nil, fmt.Errorf("failed to create transformer: %w", err)
	}

	// Get the mapping for this credential type
	mapping, err := transformer.GetMapping(session.CredentialType)
	if err != nil {
		span.SetStatus(codes.Error, "no mapping found")
		return nil, err
	}

	// Transform OIDC claims to credential claims
	claims, err := transformer.TransformClaims(session.CredentialType, authResp.Claims)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	s.log.Info("OIDC authentication successful",
		"credential_type", session.CredentialType,
		"claims_count", len(claims),
		"subject", authResp.IDToken.Subject)

	// Marshal claims to JSON for the credential
	documentData, err := json.Marshal(claims)
	if err != nil {
		span.SetStatus(codes.Error, "document marshaling failed")
		return nil, fmt.Errorf("failed to marshal document: %w", err)
	}

	// Create credential using the issuer gRPC API
	credential, err := s.createCredentialViaOIDCRP(ctx, session.CredentialType, documentData, nil)
	if err != nil {
		span.SetStatus(codes.Error, "credential creation failed")
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	// Generate credential offer for wallet
	credentialOffer, err := s.generateCredentialOfferOIDCRP(ctx, session.CredentialType, mapping.CredentialConfigID)
	if err != nil {
		span.SetStatus(codes.Error, "credential offer generation failed")
		return nil, fmt.Errorf("failed to generate credential offer: %w", err)
	}

	// Clean up session
	s.oidcrpService.DeleteSession(state)

	s.log.Info("Credential issued successfully via OIDC RP",
		"credential_type", session.CredentialType,
		"offer_id", credentialOffer["id"])

	response := map[string]interface{}{
		"status":           "success",
		"credential_type":  session.CredentialType,
		"credential":       credential,
		"credential_offer": credentialOffer,
		"message":          "OIDC authentication and credential issuance successful",
	}

	return response, nil
}

// createCredentialViaOIDCRP calls the issuer gRPC service to create a credential
func (s *Service) createCredentialViaOIDCRP(ctx context.Context, credentialType string, documentData []byte, jwk *apiv1_issuer.Jwk) (string, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:createCredentialViaOIDCRP")
	defer span.End()

	// Connect to issuer gRPC service
	conn, err := grpc.NewClient(s.cfg.Issuer.GRPCServer.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		s.log.Error(err, "Failed to connect to issuer")
		return "", fmt.Errorf("failed to connect to issuer: %w", err)
	}
	defer conn.Close()

	client := apiv1_issuer.NewIssuerServiceClient(conn)

	// Call the issuer's MakeSDJWT method
	reply, err := client.MakeSDJWT(ctx, &apiv1_issuer.MakeSDJWTRequest{
		Scope:        credentialType,
		DocumentData: documentData,
		Jwk:          jwk,
	})
	if err != nil {
		s.log.Error(err, "failed to call MakeSDJWT")
		return "", fmt.Errorf("failed to create credential: %w", err)
	}

	if reply == nil || len(reply.Credentials) == 0 {
		return "", fmt.Errorf("no credential data returned")
	}

	// Return the first credential (assuming single credential response)
	return reply.Credentials[0].Credential, nil
}

// generateCredentialOfferOIDCRP creates an OpenID4VCI credential offer
func (s *Service) generateCredentialOfferOIDCRP(ctx context.Context, credentialType string, credentialConfigID string) (map[string]interface{}, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:generateCredentialOfferOIDCRP")
	defer span.End()

	// Generate a unique pre-authorized code
	preAuthCode := fmt.Sprintf("oidcrp_%d", time.Now().UnixNano())

	// Build credential offer parameters
	params := openid4vci.CredentialOfferParameters{
		CredentialIssuer:           s.cfg.APIGW.CredentialOffers.IssuerURL,
		CredentialConfigurationIDs: []string{credentialConfigID},
		Grants: map[string]interface{}{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]interface{}{
				"pre-authorized_code": preAuthCode,
				"tx_code":             nil,
			},
		},
	}

	// Generate credential offer
	offer, err := params.CredentialOffer()
	if err != nil {
		return nil, fmt.Errorf("failed to generate credential offer: %w", err)
	}

	// Convert to map for response
	var offerMap map[string]interface{}
	offerBytes, err := json.Marshal(offer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal offer: %w", err)
	}
	if err := json.Unmarshal(offerBytes, &offerMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal offer to map: %w", err)
	}

	// Add an ID for tracking
	offerMap["id"] = preAuthCode

	return offerMap, nil
}
