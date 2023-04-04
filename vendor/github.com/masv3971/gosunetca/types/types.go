package types

import "fmt"

// SignMetaRequest is the meta data for the sign request
type SignMetaRequest struct {
	Version  int    `json:"version"`
	KeyLabel string `json:"key_label"`
	Encoding string `json:"encoding"`
	KeyType  string `json:"key_type"`
}

// UnsignedDocument is a document to sign
type UnsignedDocument struct {
	ID   string `json:"id"`
	Data string `json:"data,omitempty"` //base64 encoded
}

// SignRequest is the request for the sign endpoint
type SignRequest struct {
	Meta      SignMetaRequest    `json:"meta"`
	Documents []UnsignedDocument `json:"documents"`
}

// SignMetaReply is the meta data for the sign reply
type SignMetaReply struct {
	Version            int    `json:"version"`
	Encoding           string `json:"encoding"`
	SignerPublicKey    string `json:"signer_public_key"`
	SignatureAlgorithm string `json:"signature_algorithm"`
}

// SignedDocument is a document that has been signed
type SignedDocument struct {
	ID        string `json:"id"`
	Signature string `json:"signature"`
}

// SignReply is the reply for the sign endpoint
type SignReply struct {
	Meta            SignMetaReply    `json:"meta"`
	SignatureValues []SignedDocument `json:"signature_values"`
}

// MissingTokenReply is the reply when the token is missing
type MissingTokenReply struct {
	Message string `json:"message"`
}

// ErrorReply is the reply when there is an error
type ErrorReply struct {
	Message string `json:"message"`
}

func (e *ErrorReply) Error() string {
	if e == nil {
		return ""
	}

	return fmt.Sprintf("message: %q", e.Message)
}
