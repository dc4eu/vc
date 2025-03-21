package apiv1

import (
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
	"net/url"
	"time"
	"vc/pkg/openid4vp"
	"vc/pkg/openid4vp/cryptohelpers"
	"vc/pkg/openid4vp/jwthelpers"
)

// QRCode creates a qr code that can be used by the holder (wallet) to fetch the authorization request
func (c *Client) GenerateQRCode(ctx context.Context, request *openid4vp.DocumentTypeEnvelope) (*openid4vp.QR, error) {
	if !(request.DocumentType == openid4vp.DocumentTypeEHIC || request.DocumentType == openid4vp.DocumentTypePDA1 || request.DocumentType == openid4vp.DocumentTypeELM) {
		return nil, fmt.Errorf("document type not handled: %s", request.DocumentType)
	}

	//---key+cert gen----------
	//TODO: read from config/file and store in a secure memory keystore in Client
	veriferLongLivedEcdsaP256Private, err := cryptohelpers.GenerateECDSAKey(elliptic.P256())
	if err != nil {
		return nil, err
	}

	certData, err := cryptohelpers.GenerateSelfSignedX509Cert(veriferLongLivedEcdsaP256Private)
	//-------------------------

	clientID := "vcverifier.sunet.se" //TODO: ta in clientID via config
	sessionID := uuid.NewString()
	now := time.Now()
	ecdsaP256Private, err := cryptohelpers.GenerateECDSAKey(elliptic.P256())
	if err != nil {
		return nil, err
	}

	//TODO: vpSession ska/får mest troligt inte lagras i någon db utan måste lagra i sessionen - fixa senare när mer stabilt
	vpSession := &openid4vp.VPInteractionSession{
		SessionID: sessionID,
		SessionEphemeralKeyPair: &openid4vp.KeyPair{
			PrivateKey:         ecdsaP256Private,
			PublicKey:          ecdsaP256Private.PublicKey,
			SigningMethodToUse: jwt.SigningMethodES256,
		},
		SessionCreated: now,
		SessionExpires: now.Add(5 * time.Minute),
		DocumentType:   request.DocumentType,
		Nonce:          jwthelpers.GenerateNonce(),
		State:          uuid.NewString(),
		JTI:            uuid.NewString(),
		Authorized:     false,

		//TODO: nedan ska inte vara här men läggs här tillsvidare
		VerifierKeyPair: &openid4vp.KeyPair{
			PrivateKey:         veriferLongLivedEcdsaP256Private,
			PublicKey:          veriferLongLivedEcdsaP256Private.PublicKey,
			SigningMethodToUse: jwt.SigningMethodES256,
		},
		VerifierX5cCertDERBase64: base64.StdEncoding.EncodeToString(certData.CertDER),
	}

	err = c.db.VPInteractionSessionColl.Create(ctx, vpSession)
	if err != nil {
		return nil, err
	}

	//TODO: skapa och använd property i Verifier för baseUrl
	verifierBaseUrl := "http://172.16.50.6:8080"
	requestURI := fmt.Sprintf("%s/authorize?id=%s", verifierBaseUrl, sessionID)
	requestURIQueryEscaped := url.QueryEscape(requestURI)
	qrURI := fmt.Sprintf("openid4vp://authorize?client_id=%s&request_uri=%s", clientID, requestURIQueryEscaped)

	qrCode, err := openid4vp.GenerateQR(qrURI, requestURI, clientID, sessionID, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}

	return qrCode, nil
}

func (c *Client) GetAuthorizationRequest(ctx context.Context, sessionID string) (*openid4vp.AuthorizationRequest, error) {
	vpSession, err := c.db.VPInteractionSessionColl.Read(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if vpSession.SessionExpires.Before(time.Now()) {
		return nil, errors.New("session expired")
	}
	if vpSession.Authorized {
		return nil, errors.New("authorization request has already been requested for this session")
	}

	vpSession.Authorized = true
	vpSession.CallbackID = jwthelpers.GenerateNonce() //make it impossible to guess the complete uri to do the callback for this session (the holders https post of the vp_tokens)

	requestObjectJWS, err := c.createRequestObjectJWS(ctx, vpSession)
	if err != nil {
		return nil, err
	}

	err = c.db.VPInteractionSessionColl.Update(ctx, vpSession)
	if err != nil {
		return nil, err
	}

	return &openid4vp.AuthorizationRequest{
		RequestObjectJWS: requestObjectJWS,
	}, nil
}

func (c *Client) createRequestObjectJWS(ctx context.Context, vpSession *openid4vp.VPInteractionSession) (string, error) {
	if vpSession.DocumentType != openid4vp.DocumentTypeEHIC {
		return "", errors.New("only EHIC document is currently supported")
	}

	presentationDefinition := &openid4vp.PresentationDefinition{
		ID:          "VCEuropeanHealthInsuranceCard",
		Title:       "VC EHIC",
		Description: "Required Fields: VC type, SSN, Given Name, Family Name, Birthdate",
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID: "VCEHIC",
				Format: map[string]openid4vp.Format{
					"vc+sd-jwt": {Alg: []string{"ES256"}},
				},
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: []string{"https://vc-interop-1.sunet.se/credential/ehic/1.0", "https://vc-interop-2.sunet.se/credential/ehic/1.0", "https://satosa-test-1.sunet.se/credential/ehic/1.0", "https://satosa-test-2.sunet.se/credential/ehic/1.0", "https://satosa-dev-1.sunet.se/credential/ehic/1.0", "https://satosa-dev-2.sunet.se/credential/ehic/1.0", "EHICCredential"}}},
						{Name: "Subject", Path: []string{"$.subject"}},
						{Name: "Given Name", Path: []string{"$.subject.forename"}},
						{Name: "Family Name", Path: []string{"$.subject.family_name"}},
						{Name: "Birthdate", Path: []string{"$.subject.date_of_birth"}},
						{Name: "SSN", Path: []string{"$.social_security_pin"}},
						//TODO: {Name: "Period entitlement", Path: []string{"$.period_entitlement"}},
						{Name: "Document ID", Path: []string{"$.document_id"}},
						//TODO: {Name: "Competent Institution", Path: []string{"$.competent_institution.institution_name"}},
					},
				},
			},
		},
	}

	vpSession.PresentationDefinition = presentationDefinition

	//TODO: skapa och använd property i Verifier för baseUrl
	verifierBaseUrl := "http://172.16.50.6:8080"
	responseURI := fmt.Sprintf("%s/callback/%s/%s", verifierBaseUrl, vpSession.SessionID, vpSession.CallbackID)

	now := jwt.NewNumericDate(time.Now())
	claims := &jwthelpers.CustomClaims{
		ResponseURI:            responseURI,
		ClientIdScheme:         "x509_san_dns",        //TODO: vad ska client_id_scheme sättas till?
		ClientId:               "vcverifier.sunet.se", //TODO vad ska client_id sättas till?
		ResponseType:           "vp_token",
		ResponseMode:           "direct_post.jwt",
		State:                  vpSession.State,
		Nonce:                  vpSession.Nonce,
		PresentationDefinition: presentationDefinition,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "vcverifier.sunet.se",                         //TODO ta in iss via config
			Subject:   "todo_set_sub_value_here",                     //TODO vilket värde här för sub?
			Audience:  jwt.ClaimStrings{"https://self-issued.me/v2"}, //TODO korrekt aud?
			ExpiresAt: jwt.NewNumericDate(vpSession.SessionExpires),
			IssuedAt:  now,
			NotBefore: now,
			ID:        vpSession.JTI,
		},
	}

	jws, err := jwthelpers.CreateAndSignJWS(vpSession.VerifierKeyPair.PrivateKey, vpSession.VerifierKeyPair.SigningMethodToUse, vpSession.VerifierX5cCertDERBase64, claims)
	if err != nil {
		return "", err
	}

	return jws, nil
}

func (c *Client) Callback(ctx context.Context, sessionID string, callbackID string, request *openid4vp.AuthorizationResponse) (*openid4vp.CallbackReply, error) {
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
	if vpSession.CallbackID != callbackID {
		return nil, errors.New("callback ID does not match the one in session")
	}

	arw, err := openid4vp.NewAuthorizationResponseWrapper(request)
	if err != nil {
		return nil, err
	}
	processConfig := &openid4vp.ProcessConfig{
		ProcessType:       openid4vp.FULL_VALIDATION,
		ValidationOptions: openid4vp.ValidationOptions{},
	}
	//TODO: skicka in ref till "db" för att lagra "verified credentials" om allt är ok
	//TODO: skicka in ref till "vpSession" för att kontrollera värden mot (nonce, osv)
	//TODO: från process ska ett valideringsresultat erhållas som kan presenteras när allt blir mer klart, nu blir det bara ett err om något går fel
	//TODO: skicka in en ~crypto-store (lång och kortlivade egna nyckar och cert)
	err = arw.Process(processConfig)
	if err != nil {
		return nil, err
	}

	err = c.db.VPInteractionSessionColl.Delete(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	//TODO: vad ska returneras om validering: 1) allt OK 2) något gick fel eller ej ok
	return &openid4vp.CallbackReply{}, nil
}

func (c *Client) GetVerificationResult(ctx context.Context, sessionID string) (*openid4vp.VerificationResult, error) {
	//TODO: impl
	return &openid4vp.VerificationResult{}, nil
}
