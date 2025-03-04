package apiv1

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
	"time"
	"vc/pkg/openid4vp"
)

// QRCode creates a qr code that can be used by the holder (wallet) to fetch the authorization request
func (c *Client) GenerateQRCode(ctx context.Context, request *openid4vp.DocumentTypeEnvelope) (*openid4vp.QR, error) {
	if request.DocumentType != openid4vp.DocumentTypeEHIC {
		return nil, fmt.Errorf("document type not handled (yet!): %s", request.DocumentType)
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
		RequestObjectFetched: false,
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
	if vpSession.Nonce != nonce || vpSession.State != state {
		return nil, errors.New("nonce or state does not match session")
	}

	//TODO: kolla så det bara tillåts en enda gång per session samt lagra att steget är genomfört

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

	//TODO kolla att auth steget är OK
	//TODO fortsätt impl - glöm ej bort att sätta att request object är fetched i sessionen + kolla inledningsvis att den ej redan blivit hämtad

	//TODO: returnera en signerad jws

	return nil, nil
}
