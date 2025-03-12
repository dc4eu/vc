package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
	"math/big"
	"time"
	"vc/pkg/openid4vp"
)

// QRCode creates a qr code that can be used by the holder (wallet) to fetch the authorization request
func (c *Client) GenerateQRCode(ctx context.Context, request *openid4vp.DocumentTypeEnvelope) (*openid4vp.QR, error) {
	if !(request.DocumentType == openid4vp.DocumentTypeEHIC || request.DocumentType == openid4vp.DocumentTypePDA1) {
		return nil, fmt.Errorf("document type not handled: %s", request.DocumentType)
	}

	//---key+cert gen----------
	//TODO: read from config/file and store in a secure memory keystore in Client
	veriferLongLivedEcdsaP256Private, err := generateECDSAKey("P256")
	if err != nil {
		return nil, err
	}

	certDER, err := generateSelfSignedX509CertDER(veriferLongLivedEcdsaP256Private)
	//-------------------------

	clientID := "verifier.sunet.se" //TODO: ta in clientID via config
	sessionID := uuid.NewString()
	now := time.Now()
	ecdsaP256Private, err := generateECDSAKey("P256")
	if err != nil {
		return nil, err
	}

	//TODO: vpSession ska/får inte lagras i någon db utan måste lagra i sessionen - fixa senare när mer stabilt
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
		Nonce:          generateNonce(),
		State:          uuid.NewString(),
		JTI:            uuid.NewString(),
		Authorized:     false,

		//TODO: nedan ska inte vara här men läggs här tillsvidare
		VerifierKeyPair: &openid4vp.KeyPair{
			PrivateKey:         veriferLongLivedEcdsaP256Private,
			PublicKey:          veriferLongLivedEcdsaP256Private.PublicKey,
			SigningMethodToUse: jwt.SigningMethodES256,
		},
		VerifierX509CertDER: certDER,
	}

	err = c.db.VPInteractionSessionColl.Create(ctx, vpSession)
	if err != nil {
		return nil, err
	}

	//TODO: skapa och använd property i Verifier för baseUrl
	verifierBaseUrl := "http://172.16.50.6:8080"
	requestURI := fmt.Sprintf("%s/authorize?id=%s", verifierBaseUrl, sessionID)
	qrURI := fmt.Sprintf("openid4vp://authorize?client_id=%s&request_uri=%s", clientID, requestURI)

	qrCode, err := openid4vp.GenerateQR(qrURI, requestURI, qrcode.Medium, 256)
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
	vpSession.CallbackID = generateNonce() //make it impossible to guess the complete uri to do the callback (the holders https post of the vp_tokens)

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
	//TODO: add "client_metadata"?
}

func (c *Client) createRequestObjectJWS(ctx context.Context, vpSession *openid4vp.VPInteractionSession) (string, error) {
	if vpSession.DocumentType != openid4vp.DocumentTypeEHIC {
		return "", errors.New("only EHIC document is currently supported")
	}

	presentationDefinition := &openid4vp.PresentationDefinition{
		ID:          "VCEuropeanHealthInsuranceCard",
		Title:       "VC EHIC",
		Description: "Required Fields: VC type, SSN, Forename, Family Name, Birthdate",
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
						{Name: "Forename", Path: []string{"$.subject.forename"}},
						{Name: "Family name", Path: []string{"$.subject.family_name"}},
						{Name: "Date of birth", Path: []string{"$.subject.date_of_birth"}},
						{Name: "Social security pin", Path: []string{"$.social_security_pin"}},
						//{Name: "Period entitlement", Path: []string{"$.period_entitlement"}},
						{Name: "Document ID", Path: []string{"$.document_id"}},
						//{Name: "Competent Institution", Path: []string{"$.competent_institution.institution_name"}},
					},
				},
			},
		},
	}

	vpSession.PresentationDefinition = presentationDefinition
	err := c.db.VPInteractionSessionColl.Update(ctx, vpSession)
	if err != nil {
		return "", err
	}

	//TODO: skapa och använd property i Verifier för baseUrl
	verifierBaseUrl := "http://172.16.50.6:8080"
	responseURI := fmt.Sprintf("%s/callback/%s/%s", verifierBaseUrl, vpSession.SessionID, vpSession.CallbackID)

	now := jwt.NewNumericDate(time.Now())
	claims := &CustomClaims{
		ResponseURI:            responseURI,
		ResponseType:           "vp_token",
		ResponseMode:           "direct_post.jwt",
		State:                  vpSession.State,
		Nonce:                  vpSession.Nonce,
		PresentationDefinition: presentationDefinition,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "verifier.sunet.se",                           //TODO ta in iss via config
			Subject:   "set_sub_value_here",                          //TODO vilket värde här för sub?
			Audience:  jwt.ClaimStrings{"https://self-issued.me/v2"}, //TODO korrekt aud?
			ExpiresAt: jwt.NewNumericDate(vpSession.SessionExpires),
			IssuedAt:  now,
			NotBefore: now,
			ID:        vpSession.JTI,
		},
	}

	certBase64 := base64.StdEncoding.EncodeToString(vpSession.VerifierX509CertDER)
	jws, err := createAndSignJWS(vpSession.VerifierKeyPair.PrivateKey, vpSession.VerifierKeyPair.SigningMethodToUse, certBase64, claims)
	if err != nil {
		return "", err
	}

	return jws, nil
}

//TODO: flytta all generering av nycklar och cert till något i stil med CryptoFactory

func getCurve(curveName string) (elliptic.Curve, error) {
	switch curveName {
	case "P256":
		return elliptic.P256(), nil
	case "P384":
		return elliptic.P384(), nil
	case "P521":
		return elliptic.P521(), nil
	default:
		return nil, errors.New("unsupported curve: choose P256, P384, or P521")
	}
}

func generateECDSAKey(curveName string) (*ecdsa.PrivateKey, error) {
	curve, err := getCurve(curveName)
	if err != nil {
		return nil, err
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	if privateKey.D.Sign() <= 0 {
		return nil, errors.New("generated private key is invalid")
	}

	return privateKey, nil
}

func generateSelfSignedX509CertDER(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	subject := pkix.Name{
		Country:      []string{"SE"},
		Organization: []string{"SUNET"},
		Locality:     []string{"Stockholm"},
		SerialNumber: uuid.NewString(),
		CommonName:   "verifier.sunet.se",
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(4383 * time.Hour), //~6 months
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return certDER, nil
}

func generateSerialNumber() (*big.Int, error) {
	u := uuid.New() // Skapa ett nytt UUID (version 4)
	uBytes, err := u.MarshalBinary()
	if err != nil {
		return nil, err
	}

	serialNumber := new(big.Int).SetBytes(uBytes)
	return serialNumber, nil
}

func createAndSignJWS(privateKey interface{}, signingMethod jwt.SigningMethod, x5cCertBase64 string, claims *CustomClaims) (string, error) {
	token := jwt.NewWithClaims(signingMethod, claims)
	if x5cCertBase64 != "" {
		token.Header["x5c"] = []string{x5cCertBase64}
	}
	return token.SignedString(privateKey)

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
	if vpSession.CallbackID != callbackID {
		return nil, errors.New("callback ID does not match the one in session")
	}

	//TODO: skicka in ref till "db" för att lagra "verified credentials" om allt är ok
	//TODO: skicka in ref till "vpSession" för att kontrollera värden mot (nonce, osv)
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
