package apiv1

import (
	"context"
	"crypto/ecdsa"
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
	//TODO: Inspect user-agent type to detect cross device or same device

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
	verifierEmpEcdsaP256Private, err := cryptohelpers.GenerateECDSAKey(elliptic.P256())
	if err != nil {
		return nil, err
	}

	//TODO: vpSession får inte lagras i någon db utan måste lagra i sessionen (memmory db) - fixa senare när mer stabilt
	vpSession := &openid4vp.VPInteractionSession{
		SessionID: sessionID,
		SessionEphemeralKeyPair: &openid4vp.KeyPair{
			PrivateKey:         verifierEmpEcdsaP256Private,
			PublicKey:          verifierEmpEcdsaP256Private.PublicKey,
			SigningMethodToUse: jwt.SigningMethodES256,
		},
		SessionCreated: now,
		SessionExpires: now.Add(10 * time.Minute),
		DocumentType:   request.DocumentType,
		Nonce:          jwthelpers.GenerateNonce(),
		State:          uuid.NewString(),
		JTI:            uuid.NewString(),
		Authorized:     false,
		Status:         openid4vp.StatusQRDisplayed,
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

	qr, err := openid4vp.GenerateQR(qrURI, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}
	qr.RequestURI = requestURI
	qr.ClientID = clientID
	qr.SessionID = sessionID

	return qr, nil
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
	vpSession.Status = openid4vp.StatusQRScanned
	vpSession.CallbackID = jwthelpers.GenerateNonce() //make it impossible to guess the complete uri to do the callback for this session (the holders https post of the vp_tokens)

	requestObjectJWS, err := c.createRequestObjectJWS(ctx, vpSession)
	if err != nil {
		return nil, err
	}
	//Store in session just for dev/test purpose
	vpSession.RequestObjectJWS = requestObjectJWS

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
	responseURI := fmt.Sprintf("%s/callback/direct_post_jwt/%s/%s", verifierBaseUrl, vpSession.SessionID, vpSession.CallbackID)

	now := jwt.NewNumericDate(time.Now())
	clientMetadata, err := cryptohelpers.BuildClientMetadataFromECDSAKey(vpSession.SessionEphemeralKeyPair.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return "", err
	}
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
			Issuer: "vcverifier.sunet.se", //TODO ta in iss via config
			//Subject:   "todo_set_sub_value_here",                     //TODO vilket värde här för sub, behövs det?
			Audience:  jwt.ClaimStrings{"https://self-issued.me/v2"}, //TODO korrekt aud?
			ExpiresAt: jwt.NewNumericDate(vpSession.SessionExpires),
			IssuedAt:  now,
			NotBefore: now,
			ID:        vpSession.JTI,
		},
		ClientMetadata: clientMetadata,
	}

	jws, err := jwthelpers.CreateAndSignJWS(vpSession.VerifierKeyPair.PrivateKey, vpSession.VerifierKeyPair.SigningMethodToUse, vpSession.VerifierX5cCertDERBase64, claims)
	if err != nil {
		return "", err
	}

	return jws, nil
}

func (c *Client) Callback(ctx context.Context, sessionID string, callbackID string, request *openid4vp.AuthorizationResponse) (*openid4vp.CallbackReply, error) {
	//TODO: OBS! ändra signauren på endpointen till https://openid.net/specs/openid-4-verifiable-presentations-1_0-21.html#name-response-mode-direct_postjw
	//TODO: denna kan också vara i form av en JWE
	//TODO:
	//	21 Evaluate the Verifiable Presentation token
	//	22 Validate the Wallet Attestation.Attest the Wallet Provideris part of the Federation and the Wallet Instance is not revoked.
	//	23 Attest Credential Issuer Trust and Validate JWT Signature
	vpSession, err := c.db.VPInteractionSessionColl.Read(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	err = validateCallbackPreconditions(vpSession, callbackID)
	if err != nil {
		return nil, err
	}
	vpSession.Status = openid4vp.StatusVPTokenReceived
	err = c.db.VPInteractionSessionColl.Update(ctx, vpSession)
	if err != nil {
		return nil, err
	}

	arw, err := openid4vp.NewAuthorizationResponseWrapper(request)
	if err != nil {
		return nil, err
	}
	processConfig := &openid4vp.ProcessConfig{
		ProcessType: openid4vp.FULL_VALIDATION,
		ValidationOptions: openid4vp.ValidationOptions{
			//TODO: remove ValidationOptions when all key+crypto handling in place and work's
			SkipAllSignatureChecks: true,
		},
	}

	//TODO: skicka in ref till "vpSession" för att kontrollera värden mot (nonce, osv)
	//TODO: från process ska ett valideringsresultat erhållas som kan presenteras när allt blir mer klart, nu blir det bara ett err om något går fel
	//TODO: skicka in en ~crypto-store (lång och kortlivade egna nyckar och cert)
	err = arw.Process(processConfig)
	if err != nil {
		return nil, err
	}

	//TODO: ersätt stora delar av nedan med värden från själva valideringen
	record := &openid4vp.VerificationRecord{
		SessionID:  sessionID,
		CallbackID: callbackID,
		ValidationResult: openid4vp.ValidationMeta{
			IsValid:     true,
			ValidatedAt: time.Now().Unix(),
			ErrorInfo:   "",
		},
		PresentationSubmission: nil,
		VPResults: []*openid4vp.VPResult{
			{
				RawToken: "raw_vp_token_here",
				VCResults: []*openid4vp.VCResult{
					{
						ValidSelectiveDisclosures: []*openid4vp.Disclosure{
							{
								Salt:  "123456789",
								Key:   "ExampleKey",
								Value: "Example value",
							},
						},
					},
				},
			},
		},
	}
	err = c.db.VerificationRecordColl.Create(ctx, record)
	if err != nil {
		return nil, err
	}

	//TODO: ta bort VPInteractionSession när utvecklingen börjar vara mer klar
	//err = c.db.VPInteractionSessionColl.Delete(ctx, sessionID)
	//if err != nil {
	//	return nil, err
	//}

	//TODO: vad ska returneras tillbaka till walleten om validering: 1) allt OK 2) något gick fel eller ej ok
	return &openid4vp.CallbackReply{}, nil
}

func (c *Client) SaveRequestDataToVPSession(ctx context.Context, sessionID string, callbackID string, request *openid4vp.JsonRequestData) error {
	vpSession, err := c.db.VPInteractionSessionColl.Read(ctx, sessionID)
	if err != nil {
		return err
	}
	err = validateCallbackPreconditions(vpSession, callbackID)
	if err != nil {
		return err
	}

	vpSession.AuthorisationResponseDebugData = request
	err = c.db.VPInteractionSessionColl.Update(ctx, vpSession)
	if err != nil {
		return err
	}

	return nil
}

func validateCallbackPreconditions(vpSession *openid4vp.VPInteractionSession, callbackID string) error {
	if vpSession.SessionExpires.Before(time.Now()) {
		return errors.New("session expired")
	}
	if !vpSession.Authorized {
		return errors.New("not authorized in session")
	}
	if vpSession.CallbackID != callbackID {
		return errors.New("callback ID does not match the one in session")
	}
	if vpSession.Status == openid4vp.StatusVPTokenReceived {
		return errors.New("callback already performed in session")
	}
	return nil
}

func (c *Client) GetVerificationResult(ctx context.Context, sessionID string) (*openid4vp.VerificationResult, error) {
	status := openid4vp.StatusUnknown
	vpSession, _ := c.db.VPInteractionSessionColl.Read(ctx, sessionID)
	if vpSession != nil {
		status = vpSession.Status
	}

	var data any
	if vpSession == nil || vpSession.Status == openid4vp.StatusVPTokenReceived || vpSession.Status == openid4vp.StatusCompleted {
		verificationRecord, _ := c.db.VerificationRecordColl.Read(ctx, sessionID)
		//TODO: filter what data in verificationRecord to expose (if not nil or any error)
		data = verificationRecord
	}

	return &openid4vp.VerificationResult{
		Status: string(status),
		Data:   data,
	}, nil
}

type VPFlowDebugInfoReply struct {
	SessionID                   string                          `json:"session_id"`
	TimestampUTC                time.Time                       `json:"timestamp_utc"`
	VPSession                   *openid4vp.VPInteractionSession `json:"vp_session,omitempty"`
	VPSessionReadError          error                           `json:"vp_session_read_error,omitempty"`
	VerificationRecord          *openid4vp.VerificationRecord   `json:"verification_record,omitempty"`
	VerificationRecordReadError error                           `json:"verification_record_read_error,omitempty"`
}

type VPFlowDebugInfoRequest struct {
	SessionID string `json:"session_id" validate:"required,uuid"`
}

func (c *Client) GetVPFlowDebugInfo(ctx context.Context, request *VPFlowDebugInfoRequest) (*VPFlowDebugInfoReply, error) {
	if c.cfg.Common.Production {
		return nil, errors.New("endpoint disabled in production")
	}

	vpSession, errVPSession := c.db.VPInteractionSessionColl.Read(ctx, request.SessionID)
	verificationRecord, errVerRec := c.db.VerificationRecordColl.Read(ctx, request.SessionID)

	if vpSession != nil && vpSession.AuthorisationResponseDebugData != nil && len(vpSession.AuthorisationResponseDebugData.Body) != 0 {
		fmt.Println("vpSession.AuthorisationResponseDebugData.Body as string:", string(vpSession.AuthorisationResponseDebugData.Body))
		//var generic map[string]interface{}
		//err := json.Unmarshal(vpSession.AuthorisationResponseDebugData.Body, &generic)
		//if err != nil {
		//	return nil, fmt.Errorf("Failed to parse JSON: %w", err)
		//}
		//fmt.Println("Body as generic struct:", generic)
	}

	return &VPFlowDebugInfoReply{
		SessionID:                   request.SessionID,
		TimestampUTC:                time.Now().UTC(),
		VPSession:                   vpSession,
		VPSessionReadError:          errVPSession,
		VerificationRecord:          verificationRecord,
		VerificationRecordReadError: errVerRec,
	}, nil
}
