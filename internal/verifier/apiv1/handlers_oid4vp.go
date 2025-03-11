package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
	"time"
	"vc/pkg/openid4vp"
)

// QRCode creates a qr code that can be used by the holder (wallet) to fetch the authorization request
func (c *Client) GenerateQRCode(ctx context.Context, request *openid4vp.DocumentTypeEnvelope) (*openid4vp.QR, error) {
	if !(request.DocumentType == openid4vp.DocumentTypeEHIC || request.DocumentType == openid4vp.DocumentTypePDA1) {
		return nil, fmt.Errorf("document type not handled: %s", request.DocumentType)
	}

	//OBS!! se filen "vp endpoints.txt" på skrivbordet

	sessionID := uuid.NewString()
	now := time.Now()
	nonce := generateNonce()
	state := uuid.NewString()
	vpSession := &openid4vp.VPInteractionSession{
		SessionID:            sessionID,
		SessionCreated:       now,
		SessionExpires:       now.Add(5 * time.Minute),
		Status:               "pending",
		DocumentType:         request.DocumentType,
		Nonce:                nonce,
		State:                state,
		Authorized:           false,
		RequestObjectFetched: false,
		CallbackID:           generateNonce(),
	}

	//TODO: skapa och använd property i Verifier för baseUrl
	baseUrl := "http://172.16.50.6:8080"
	authorizeURL := fmt.Sprintf("%s/authorize?session_id=%s&scope=openid&nonce=%s&state=%s", baseUrl, sessionID, nonce, state)

	err := c.db.VPInteractionSessionColl.Create(ctx, vpSession)
	if err != nil {
		return nil, err
	}

	qrCode, err := openid4vp.GenerateQR(authorizeURL, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}

	return qrCode, nil
}

func generateNonce() string {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		return uuid.NewString()
	}
	return base64.RawURLEncoding.EncodeToString(nonce)
}

func (c *Client) Authorize(ctx context.Context, sessionID string, nonce string, state string) (*openid4vp.AuthorizationRequest, error) {
	vpSession, err := c.db.VPInteractionSessionColl.Read(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if vpSession.SessionExpires.Before(time.Now()) {
		return nil, errors.New("session expired")
	}
	if vpSession.Nonce != nonce || vpSession.State != state {
		return nil, errors.New("nonce or state does not match session")
	}
	if vpSession.Authorized {
		return nil, errors.New("authorize has already been performed")
	}

	vpSession.Authorized = true
	err = c.db.VPInteractionSessionColl.Update(ctx, vpSession)
	if err != nil {
		return nil, err
	}

	//TODO: add auth here if needed
	//TODO: log that the QR has been followed

	//TODO: skapa och använd property i Verifier för baseUrl
	baseUrl := "http://172.16.50.6:8080"
	requestURI := fmt.Sprintf("%s/request-object/%s", baseUrl, sessionID)

	return &openid4vp.AuthorizationRequest{
		RequestURI: requestURI,
		Nonce:      vpSession.Nonce,
	}, nil
}

func (c *Client) GetRequestObject(ctx context.Context, sessionID string) (*openid4vp.RequestObjectResponse, error) {
	vpSession, err := c.db.VPInteractionSessionColl.Read(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if vpSession.SessionExpires.Before(time.Now()) {
		return nil, errors.New("session expired")
	}
	if !vpSession.Authorized {
		return nil, errors.New("not authorized in session")
	}
	if vpSession.RequestObjectFetched {
		return nil, errors.New("request object has already been fetched once in session")
	}

	vpSession.RequestObjectFetched = true
	err = c.db.VPInteractionSessionColl.Update(ctx, vpSession)
	if err != nil {
		return nil, err
	}

	requestObjectJWS, err := c.createRequestObjectJWS(ctx, vpSession)
	if err != nil {
		return nil, err
	}

	return &openid4vp.RequestObjectResponse{
		RequestObjectJWS: requestObjectJWS,
	}, nil
}

type CustomClaims struct {
	jwt.RegisteredClaims
	ResponseURI            string                            `json:"response_uri"`
	ClientIdScheme         string                            `json:"client_id_scheme"`
	ClientId               string                            `json:"client_id"`
	ResponseType           string                            `json:"response_type"`
	ResponseMode           string                            `json:"response_mode"`
	State                  string                            `json:"state"`
	Nonce                  string                            `json:"nonce"`
	PresentationDefinition *openid4vp.PresentationDefinition `json:"presentation_definition,omitempty"`
	//TODO: add "client_metadata"
}

func (c *Client) createRequestObjectJWS(ctx context.Context, vpSession *openid4vp.VPInteractionSession) (string, error) {

	if vpSession.DocumentType != openid4vp.DocumentTypeEHIC {
		return "", errors.New("only EHIC document is currently supported")
	}

	presentationDefinition := &openid4vp.PresentationDefinition{
		//TODO fyll nedan baserat på documentType samt red ut vilket schema som gäller för grekerna???
		ID:      "EuropeanHealthInsuranceCard",
		Name:    "",
		Purpose: "",
		Format: openid4vp.ClaimFormatDesignations{
			VCSDJWT: &openid4vp.AlgorithmDefinition{
				Alg: []string{"ES256"},
			},
		},
		Frame:                  nil,
		SubmissionRequirements: nil,
		InputDescriptors:       nil,
	}

	vpSession.PresentationDefinition = presentationDefinition
	err := c.db.VPInteractionSessionColl.Update(ctx, vpSession)
	if err != nil {
		return "", err
	}

	//TODO: skapa och använd property i Verifier för baseUrl
	baseUrl := "http://172.16.50.6:8080"
	responseURI := fmt.Sprintf("%s/callback/%s/%s", baseUrl, vpSession.SessionID, vpSession.CallbackID)

	claims := &CustomClaims{
		ResponseURI:            responseURI,
		ResponseType:           "vp_token",
		ResponseMode:           "direct_post.jwt",
		Nonce:                  vpSession.Nonce,
		PresentationDefinition: presentationDefinition,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "verifier.sunet.se",
			Subject:   "user123", //TODO vilket värde här för sub?
			Audience:  jwt.ClaimStrings{"https://self-issued.me/v2"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.NewString(),
		},
	}

	//TODO: replace with the verifier real keys where the public is exposed at some endpoint?
	ecdsaP256Private, _, err := generateECDSAKeyPair(elliptic.P256())

	jws, err := createAndSignJWS(ecdsaP256Private, jwt.SigningMethodES256, claims)
	if err != nil {
		return "", err
	}

	return jws, nil
}

func generateECDSAKeyPair(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func createAndSignJWS(privateKey interface{}, signingMethod jwt.SigningMethod, claims *CustomClaims) (string, error) {
	claims.IssuedAt = jwt.NewNumericDate(time.Now())
	token := jwt.NewWithClaims(signingMethod, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func (c *Client) Callback(ctx context.Context, sessionID string, callbackID string, request *openid4vp.AuthorizationResponse) (any, error) {
	vpSession, err := c.db.VPInteractionSessionColl.Read(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if vpSession.SessionExpires.Before(time.Now()) {
		return nil, errors.New("session expired")
	}
	if !vpSession.Authorized {
		return nil, errors.New("not authorized in session")
	}
	if !vpSession.RequestObjectFetched {
		return nil, errors.New("request object has not been fetched in session")
	}
	if vpSession.CallbackID != callbackID {
		return nil, errors.New("callback ID does not match the one in session")
	}

	//TODO: skicka in ref till db för att lagra "verified credentials" om allt är ok
	arw, err := openid4vp.NewAuthorizationResponseWrapper(request)
	if err != nil {
		return nil, err
	}
	processConfig := &openid4vp.ProcessConfig{
		ProcessType:       openid4vp.FULL_VALIDATION,
		ValidationOptions: openid4vp.ValidationOptions{},
	}
	//TODO: från process ska ett valideringsresultat erhållas som kan presenteras när allt blir mer klart, nu blir det bara ett err om något går fel
	err = arw.Process(processConfig)
	if err != nil {
		return nil, err
	}

	err = c.db.VPInteractionSessionColl.Delete(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	//TODO: vad ska returneras om validering: 1) allt OK 2) något gick fel eller ej ok
	return nil, nil
}
