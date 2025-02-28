package openid4vp

import "time"

const (
	DocumentTypeEHIC = "EHIC"
	DocumentTypePDA1 = "PDA1"
)

// QR is a collection of fields representing a QR code
type QR struct {
	Base64Image string `json:"base64_image" bson:"base64_image" validate:"required"`
	URL         string `json:"url" bson:"url" validate:"required"`
}

type DocumentTypeEnvelope struct {
	DocumentType string `json:"document_type" bson:"document_type" validate:"required,oneof=PDA1 EHIC"`
}

// TODO: lagra med sessionID som nyckel
type VPInteractionSession struct {
	SessionID                 string    `json:"session_id"`    //key == must be unique i coll (UUID1)
	DocumentType              string    `json:"document_type"` //type of document the presentation_definition will request from the holder
	State                     string    `json:"state"`         //~UUID2
	Nonce                     string    `json:"nonce"`         //~UUID3
	CreatedAt                 time.Time `json:"created_at"`
	ExpiresAt                 time.Time `json:"expires_at"`
	PresentationDefinitionURI string    `json:"presentation_definition_uri"` // .../{SessionID}
	RedirectURI               string    `json:"redirect_uri"`                //.../{SessionID}
}
