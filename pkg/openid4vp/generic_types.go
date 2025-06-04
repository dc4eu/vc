package openid4vp

import (
	"crypto"
	"github.com/golang-jwt/jwt/v5"
	"sync/atomic"
	"time"
)

const (
	InteractionStatusQRDisplayed                   InteractionStatus = "qr_displayed"
	InteractionStatusQRScanned                     InteractionStatus = "qr_scanned"
	InteractionStatusAuthorizationResponseReceived InteractionStatus = "authorization_response_received"
	InteractionStatusUnknown                       InteractionStatus = "unknown"

	VerificationResultVerified VerificationResult = "verified"
	VerificationResultRejected VerificationResult = "rejected"
	VerificationResultError    VerificationResult = "error"
)

type QRRequest struct {
	PresentationRequestTypeID string `json:"presentation_request_type_id,omitempty" bson:"presentation_request_type_id" validate:"omitempty,oneof=VCEHIC VCELM VCPID EuropeanHealthInsuranceCard MinimalPIDAndEuropeanHealthInsuranceCard"`
	EncryptDirectPostJWT      bool   `json:"encrypt_direct_post_jwt,omitempty" bson:"encrypt_direct_post_jwt" validate:"omitempty"`

	// Deprecated: to be removed after Ladok has adapted, use PresentationRequestTypeID instead
	DocumentType string `json:"document_type,omitempty" bson:"document_type" validate:"omitempty,oneof=urn:edui:diploma:1 urn:eudi:ehic:1 urn:edui:elm:1 urn:edui:micro_credential:1 urn:eudi:pda1:1 urn:eu.europa.ec.eudi:pid:1"`
}

type PresentationRequestType struct {
	ID          string `json:"id" bson:"id" validate:"required"`
	Title       string `json:"title" bson:"title" validate:"required"`
	Description string `json:"description" bson:"description" validate:"required"`
}

// QRReply is a collection of fields representing a QRReply code
type QRReply struct {
	Base64Image string `json:"base64_image" bson:"base64_image" validate:"required"`
	URI         string `json:"uri" bson:"uri" validate:"required"`
	RequestURI  string `json:"request_uri" bson:"request_uri" validate:"required"`
	ClientID    string `json:"client_id" bson:"client_id" validate:"required"`
	SessionID   string `json:"session_id" bson:"session_id" validate:"required"`
}

type KeyType string

const (
	KeyTypeRSA     KeyType = "RSA"
	KeyTypeRSAPSS  KeyType = "RSAPSS"
	KeyTypeEC      KeyType = "EC"
	KeyTypeOKP     KeyType = "OKP"
	KeyTypeEd25519 KeyType = "Ed25519"
	KeyTypeEd448   KeyType = "Ed448"
	KeyTypeX25519  KeyType = "X25519"
	KeyTypeX448    KeyType = "X448"
	KeyTypeDSA     KeyType = "DSA"
	KeyTypeUnknown KeyType = "UNKNOWN"
)

type KeyPair struct {
	KeyType            KeyType
	PrivateKey         crypto.PrivateKey `json:"private_key" bson:"private_key" validate:"required"`
	PublicKey          crypto.PublicKey  `json:"public_key" bson:"public_key" validate:"required"`
	SigningMethodToUse jwt.SigningMethod

	//not to be used in production
	XBase64URLEncoded string `json:"x_as_base64_url,omitempty" bson:"x_as_base64_url" validate:"optional"`
	YBase64URLEncoded string `json:"y_as_base64_url,omitempty" bson:"y_as_base64_url" validate:"optional"`
	DBase64URLEncoded string `json:"d_as_base64_url,omitempty" bson:"d_as_base64_url" validate:"optional"`
}
type CertData struct {
	CertDER []byte
	CertPEM []byte
}

type VPInteractionSession struct {
	SessionID               string            `json:"session_id"` //key == must be unique i coll (UUID1)
	Status                  InteractionStatus `json:"interaction_status"`
	SessionEphemeralKeyPair *KeyPair          `json:"session_ephemeral_key_pair"`
	SessionCreated          time.Time         `json:"session_created"`
	SessionExpires          time.Time         `json:"session_expires"`
	// DEPRECATED: use PresentationRequestTypeID
	DocumentType              string                  `json:"document_type"` //type of document (vc) the presentation_definition will request from the holder
	PresentationRequestTypeID string                  `json:"presentation_request_type_id"`
	Nonce                     string                  `json:"nonce"`
	State                     string                  `json:"state"` //UUID2
	Authorized                bool                    `json:"authorized"`
	CallbackID                string                  `json:"callback_id"`
	JTI                       string                  `json:"jti"`
	PresentationDefinition    *PresentationDefinition `json:"presentation_definition"`
	EncryptDirectPostJWT      bool                    `json:"encrypt_direct_post_jwt"`

	VerifierKeyPair                *KeyPair         `json:"-"`
	VerifierX5cCertDERBase64       string           `json:"-"`
	RequestObjectJWS               string           `json:"request_object_jws,omitempty"`
	AuthorisationResponseDebugData *JsonRequestData `json:"authorisation_response_debug_data,omitempty"`
	// Deprecated: ta bort när wwW bara gör ett anrop och behovet att kolla detta inte längre finns kvar
	CountNbrCallsToGetAuthorizationRequest int64 `json:"count_nbr_calls_to_get_authorization_request,omitempty"` //TODO: Behöver reda ut hur många gånger plånboken verkligen anropar denna (verkar som mer än 1ggr per session)???
}

func (vpSession *VPInteractionSession) IncrementCountNbrCallsToGetAuthorizationRequest() {
	atomic.AddInt64(&vpSession.CountNbrCallsToGetAuthorizationRequest, 1)
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

type CallbackReply struct {
}

type VerificationRecord struct {
	Sequence               int64                   `json:"sequence" bson:"sequence" validate:"required"`
	SessionID              string                  `json:"session_id" bson:"session_id" validate:"required"` //Key
	CallbackID             string                  `json:"callback_id" bson:"callback_id" validate:"required"`
	VerificationMeta       *VerificationMeta       `json:"verification_meta" bson:"verification_meta" validate:"required"`
	PresentationSubmission *PresentationSubmission `json:"presentation_submission,omitempty" bson:"presentation_submission"`
	VPResults              []*VPResult             `json:"vp_results" bson:"vp_results"`
}

type VerificationResult string
type VerificationMeta struct {
	VerificationResult VerificationResult `json:"verification_result" bson:"verification_result" validate:"required"`
	VerifiedAtUnix     int64              `json:"verified_at_unix" bson:"verified_at_unix"  validate:"required"` //Unix (UTC)
	Error              string             `json:"error,omitempty" bson:"error,omitempty"`
	ErrorDescription   string             `json:"error_description,omitempty" bson:"error_description,omitempty"`
	ErrorURI           string             `json:"error_uri,omitempty" bson:"error_uri,omitempty"`
}

type VPResult struct {
	RawToken  string      `json:"raw_token" bson:"raw_token"`
	VCResults []*VCResult `json:"vc_results" bson:"vc_results"`
}

type VCResult struct {
	RawJWT string `json:"raw_jwt" bson:"raw_jwt"`
	Format string `json:"format" bson:"format"`
	JWTTyp string `json:"jwt_typ" bson:"jwt_typ"`
	//VCT                       string                 `json:"vct" bson:"vct"`
	VCTM                      map[string]interface{} `json:"vctm" bson:"vctm"`
	ValidSelectiveDisclosures []*Disclosure          `json:"valid_selective_disclosures" bson:"valid_selective_disclosures"`
	Claims                    map[string]interface{} `json:"claims" bson:"claims"`
}
