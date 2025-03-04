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
	SessionID            string    `json:"session_id"` //key == must be unique i coll (UUID1)
	SessionCreated       time.Time `json:"session_created"`
	SessionExpires       time.Time `json:"session_expires"`
	Status               string    `json:"status"`
	DocumentType         string    `json:"document_type"` //type of document (vc) the presentation_definition will request from the holder
	Nonce                string    `json:"nonce"`
	State                string    `json:"state"` //UUID2
	RequestObjectFetched bool      `json:"request_object_fetched"`
}

type AuthorizationRequest struct {
	RequestURI string `json:"request_uri"`
	Nonce      string `json:"nonce"`
}

type RequestObjectResponse struct {
	RequestObjectJWS string `json:"request_object"`
}
