package openid4vp

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

const (
	DocumentTypeEHIC = "EHIC"
	DocumentTypePDA1 = "PDA1"
)

// QR is a collection of fields representing a QR code
type QR struct {
	Base64Image string `json:"base64_image" bson:"base64_image" validate:"required"`
	URI         string `json:"uri" bson:"uri" validate:"required"`
	RequestURI  string `json:"request_uri" bson:"request_uri" validate:"required"`
}

type DocumentTypeEnvelope struct {
	DocumentType string `json:"document_type" bson:"document_type" validate:"required,oneof=PDA1 EHIC"`
}

type KeyPair struct {
	PrivateKey         interface{} `json:"private_key" bson:"private_key" validate:"required"`
	PublicKey          interface{} `json:"public_key" bson:"public_key" validate:"required"`
	SigningMethodToUse jwt.SigningMethod
}

type VPInteractionSession struct {
	SessionID               string `json:"session_id"` //key == must be unique i coll (UUID1)
	SessionEphemeralKeyPair *KeyPair
	SessionCreated          time.Time `json:"session_created"`
	SessionExpires          time.Time `json:"session_expires"`
	DocumentType            string    `json:"document_type"` //type of document (vc) the presentation_definition will request from the holder
	Nonce                   string    `json:"nonce"`
	State                   string    `json:"state"` //UUID2
	Authorized              bool      `json:"authorized"`
	CallbackID              string    `json:"callback_id"`
	JTI                     string    `json:"jti"`
	PresentationDefinition  *PresentationDefinition
	//---------------
	VerifierKeyPair *KeyPair
	//VerifierX509CertDER []byte
	VerifierX5cCertDERBase64 string
}

type AuthorizationRequest struct {
	RequestObjectJWS string `json:"request_object"`
}
