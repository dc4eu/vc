package types

import (
	"fmt"
)

// Document is the general document type
type Document struct {
	TransactionID string `json:"transaction_id" bson:"transaction_id" redis:"transaction_id"`
	Data          string `json:"data" bson:"data" redis:"data"`
	Error         string `json:"error,omitempty" bson:"error" redis:"error"`
	Message       string `json:"message,omitempty" bson:"-" redis:"-"`
	RevokedTS     int64  `json:"revoked_ts,omitempty" bson:"revoked_ts" redis:"revoke_ts"`
	ModifyTS      int64  `json:"modify_ts,omitempty" bson:"modify_ts" redis:"modify_ts"`
	CreateTS      int64  `json:"create_ts,omitempty" mongo:"create_ts" redis:"create_ts"`
	Reason        string `json:"reason,omitempty"`
	Location      string `json:"location,omitempty"`
}

// Validation is the reply for the validate endpoint
type Validation struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// SignRequest is the request for the sign endpoint
type SignRequest struct {
	*Document
	// TransactionID string `json:"transaction_id"`
	// PDFB64Data    string `json:"pdf_b64_data,omitempty" redis:"data"` //base64 encoded
}

// SignReply is the reply for the sign endpoint
//type SignReply struct {
//	*Document
////	TransactionID    string `json:"transaction_id"`
////	SignedPDFB64Data string `json:" signed_pdf_b64_data" redis:"data"`
//}

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
