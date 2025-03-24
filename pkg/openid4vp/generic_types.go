package openid4vp

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

const (
	DocumentTypeEHIC = "EHIC"
	DocumentTypeELM  = "ELM"
	DocumentTypePDA1 = "PDA1"

	StatusQRDisplayed     InteractionStatus = "qr_displayed"
	StatusQRScanned       InteractionStatus = "qr_scanned"
	StatusVPTokenReceived InteractionStatus = "vp_token_received"
	StatusCompleted       InteractionStatus = "completed"
	StatusUnknown         InteractionStatus = "unknown"
)

// QR is a collection of fields representing a QR code
type QR struct {
	Base64Image string `json:"base64_image" bson:"base64_image" validate:"required"`
	URI         string `json:"uri" bson:"uri" validate:"required"`
	RequestURI  string `json:"request_uri" bson:"request_uri" validate:"required"`
	ClientID    string `json:"client_id" bson:"client_id" validate:"required"`

	//only for internal use
	SessionID string `json:"-"`
}

type DocumentTypeEnvelope struct {
	DocumentType string `json:"document_type" bson:"document_type" validate:"required,oneof=EHIC ELM PDA1 "`
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
	Status                  InteractionStatus `json:"status"`
	//---------------
	VerifierKeyPair *KeyPair
	//VerifierX509CertDER []byte
	VerifierX5cCertDERBase64 string
}

type InteractionStatus string

type AuthorizationRequest struct {
	RequestObjectJWS string `json:"request_object"`
}

type VerificationResult struct {
	Status string `json:"status,omitempty"`
	Data   any    `json:"data"`
}

type CallbackReply struct {
}

type VerificationRecord struct {
	SessionID              string                  `json:"session_id" bson:"session_id" validate:"required"` //Key
	CallbackID             string                  `json:"callback_id" bson:"callback_id" validate:"required"`
	ValidationResult       ValidationMeta          `json:"validation_meta" bson:"validation_meta" validate:"required"`
	PresentationSubmission *PresentationSubmission `json:"presentation_submission" bson:"presentation_submission" validate:"required"`
	VPResults              []*VPResult             `json:"vp_results" bson:"vp_results"`
}

type ValidationMeta struct {
	IsValid     bool   `json:"is_valid" bson:"is_valid" validate:"required"`
	ValidatedAt int64  `bson:"validated_at" json:"validated_at" validate:"required"` //Unix UTC
	ErrorInfo   string `json:"error_info,omitempty" bson:"error_info,omitempty"`
}

type VPResult struct {
	RawToken  string      `json:"raw_token" bson:"raw_token" validate:"required"`
	VCResults []*VCResult `json:"vc_results" bson:"vc_results"`
}

type VCResult struct {
	ValidSelectiveDisclosures []*Disclosure `json:"valid_selective_disclosures" bson:"valid_selective_disclosures"`
}
