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

	//Only to simplify dev and test
	SessionID string `json:"session_id" bson:"session_id" validate:"required"`
}

type DocumentTypeEnvelope struct {
	DocumentType string `json:"document_type" bson:"document_type" validate:"required,oneof=EHIC ELM PDA1 "`
}

type KeyPair struct {
	PrivateKey         interface{} `json:"private_key" bson:"private_key" validate:"required"`
	PublicKey          interface{} `json:"public_key" bson:"public_key" validate:"required"`
	SigningMethodToUse jwt.SigningMethod
}

type CertData struct {
	CertDER []byte
	CertPEM []byte
}

type VPInteractionSession struct {
	SessionID               string                  `json:"session_id"` //key == must be unique i coll (UUID1)
	Status                  InteractionStatus       `json:"status"`
	SessionEphemeralKeyPair *KeyPair                `json:"session_ephemeral_key_pair"`
	SessionCreated          time.Time               `json:"session_created"`
	SessionExpires          time.Time               `json:"session_expires"`
	DocumentType            string                  `json:"document_type"` //type of document (vc) the presentation_definition will request from the holder
	Nonce                   string                  `json:"nonce"`
	State                   string                  `json:"state"` //UUID2
	Authorized              bool                    `json:"authorized"`
	CallbackID              string                  `json:"callback_id"`
	JTI                     string                  `json:"jti"`
	PresentationDefinition  *PresentationDefinition `json:"presentation_definition"`

	//TODO: Below is just for dev/test purpose and must be removed before production
	VerifierKeyPair *KeyPair `json:"-"`
	//VerifierX509CertDER []byte
	VerifierX5cCertDERBase64       string           `json:"-"`
	RequestObjectJWS               string           `json:"request_object_jws,omitempty"`
	AuthorisationResponseDebugData *JsonRequestData `json:"authorisation_response_debug_data,omitempty"`
}

type JsonRequestData struct {
	Method           string                 `json:"method"`
	URL              string                 `json:"url"`
	Proto            string                 `json:"proto"`
	ProtoMajor       int                    `json:"proto_major"`
	ProtoMinor       int                    `json:"proto_minor"`
	Header           map[string][]string    `json:"header"`
	Body             []byte                 `json:"body"`
	ContentLength    int64                  `json:"content_length"`
	TransferEncoding []string               `json:"transfer_encoding"`
	Close            bool                   `json:"close"`
	Host             string                 `json:"host"`
	Form             map[string][]string    `json:"form"`
	PostForm         map[string][]string    `json:"post_form"`
	MultipartForm    map[string][]string    `json:"multipart_form"`
	Trailer          map[string][]string    `json:"trailer"`
	RemoteAddr       string                 `json:"remote_addr"`
	RequestURI       string                 `json:"request_uri"`
	TLS              map[string]interface{} `json:"tls"`
	ClientIP         string                 `json:"client_ip"`
	ContentType      string                 `json:"content_type"`
	UserAgent        string                 `json:"user_agent"`
	Referer          string                 `json:"referer"`
	Cookies          []map[string]string    `json:"cookies"`
	FullPath         string                 `json:"full_path"`
	Handler          string                 `json:"handler"`
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
	Sequence               int64                   `json:"sequence" bson:"sequence" validate:"required"`
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
	VCT                       string                 `json:"vct" bson:"vct" validate:"required"`
	ValidSelectiveDisclosures []*Disclosure          `json:"valid_selective_disclosures" bson:"valid_selective_disclosures"`
	Claims                    map[string]interface{} `json:"claims" bson:"claims"`
}
