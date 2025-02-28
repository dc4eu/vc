package apiv1

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
	"time"
	"vc/pkg/openid4vp"
)

// QRCode creates a qr code that can be used by the holder (wallet) to fetch the authorization request incl. presentation definition
func (c *Client) QRCode(ctx context.Context, request *openid4vp.DocumentTypeEnvelope) (*openid4vp.QR, error) {
	if request.DocumentType != "EHIC" {
		return nil, fmt.Errorf("document type not handled (yet!): %s", request.DocumentType)
	}

	//TODO: red ut allt nedan - dvs vad ska qr-koden ha för uri?
	//https://wallet.example.com/auth?
	//	response_type=vp_token&
	//		client_id=https://verifier.sunet.se&
	//	redirect_uri=https://verifier.sunet.se/callback/{session_id}&
	//	scope=openid&
	//		nonce=550e8400-e29b-41d4-a716-446655440000&
	//		state=79a1df2b-87ee-4ff8-a2bc-d5a59b9bece4&
	//		presentation_definition_uri=https://verifier.sunet.se/presentation-definition/{session_id}&
	//	response_mode=form_post

	sessionID := uuid.NewString()
	vpSession := &openid4vp.VPInteractionSession{
		SessionID:                 sessionID,
		DocumentType:              request.DocumentType,
		State:                     uuid.NewString(),
		Nonce:                     uuid.NewString(),
		CreatedAt:                 time.Now(),
		ExpiresAt:                 time.Now().Add(5 * time.Minute),
		PresentationDefinitionURI: "https://verifier.sunet.se/presentation_definition/" + sessionID, //TODO: PresentationDefinitionURI
		RedirectURI:               "https://verifier.sunet.se/callback/" + sessionID,                //TODO: RedirectURI (endpoint vp'n ska postad till)
	}

	err := c.db.VPInteractionSessionColl.Create(ctx, vpSession)
	if err != nil {
		return nil, err
	}

	qrCode, err := openid4vp.GenerateQR(vpSession.PresentationDefinitionURI, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}

	return qrCode, nil
}
