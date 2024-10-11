package helpers

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/moogar0880/problems"
)

var (
	// ErrDocumentIsRevoked is returned when a document is revoked
	ErrDocumentIsRevoked = NewError("document_is_revoked")
	// ErrNoTransactionID is returned when transactionID is not present
	ErrNoTransactionID = NewError("no_transaction_id")

	// ErrNoDocumentFound is returned when no document is found
	ErrNoDocumentFound = NewError("no_document_found")

	// ErrDocumentAlreadyExists is returned when a document already exists
	ErrDocumentAlreadyExists = NewError("document_already_exists")

	// ErrNoDocumentData is returned when no document_data is found
	ErrNoDocumentData = NewError("no_document_data")

	// ErrNoIdentityFound is returned when no identity is found
	ErrNoIdentityFound = NewError("no_identity_found")

	// ErrDuplicateKey is returned when a duplicate key is found
	ErrDuplicateKey = NewError("duplicate_key")

	// ErrNoRevocationID is returned when no revocation_id is found
	ErrNoRevocationID = NewError("no_revocation_id")

	// ErrPrivateKeyMissing error for empty private key
	ErrPrivateKeyMissing = errors.New("ERR_PRIVATE_KEY_MISSING")

	// ErrNoKnownDocumentType error for no known document type
	ErrNoKnownDocumentType = errors.New("ERR_NO_KNOWN_DOCUMENT_TYPE")
)

// Error is a struct that represents an error
type Error struct {
	Title   string      `json:"title" `
	Details interface{} `json:"details" xml:"details"`
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Details == nil {
		return fmt.Sprintf("Error: [%s]", e.Title)
	}
	return fmt.Sprintf("Error: [%s] %+v", e.Title, e.Details)
}

type ErrorResponse struct {
	Error *Error `json:"error"`
}

func NewError(id string) *Error {
	return &Error{Title: id}
}

func NewErrorDetails(id string, details any) *Error {
	return &Error{Title: id, Details: details}
}

// NewErrorFromError creates a new Error from an error
func NewErrorFromError(err error) *Error {
	if err == nil {
		return nil
	}
	if pbErr, ok := err.(*Error); ok {
		return pbErr
	}
	if jsonUnmarshalTypeError, ok := err.(*json.UnmarshalTypeError); ok {
		return &Error{Title: "json_type_error", Details: formatJSONUnmarshalTypeError(jsonUnmarshalTypeError)}
	}
	if jsonSyntaxError, ok := err.(*json.SyntaxError); ok {
		return &Error{Title: "json_syntax_error", Details: map[string]any{"position": jsonSyntaxError.Offset, "error": jsonSyntaxError.Error()}}
	}
	if validatorErr, ok := err.(validator.ValidationErrors); ok {
		return &Error{Title: "validation_error", Details: formatValidationErrors(validatorErr)}
	}

	return NewErrorDetails("internal_server_error", err.Error())
}

func formatValidationErrors(err validator.ValidationErrors) []map[string]any {
	v := make([]map[string]any, 0)
	for _, e := range err {
		splits := strings.SplitN(e.Namespace(), ".", 2)
		v = append(v, map[string]any{
			"field":           e.Field(),
			"namespace":       splits[1],
			"type":            e.Kind().String(),
			"validation":      e.Tag(),
			"validationParam": e.Param(),
			"value":           e.Value(),
		})
	}
	return v
}

func formatJSONUnmarshalTypeError(err *json.UnmarshalTypeError) []map[string]any {
	return []map[string]any{
		{
			"field":    err.Field,
			"expected": err.Type.Kind().String(),
			"actual":   err.Value,
		},
	}
}

func Problem404() (*problems.DefaultProblem, error) {
	notFound := problems.NewDetailedProblem(404, "Not a valid endpoint")
	if err := problems.ValidateProblem(notFound); err != nil {
		return nil, err
	}

	return notFound, nil
}
