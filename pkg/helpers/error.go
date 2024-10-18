package helpers

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/moogar0880/problems"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	// ErrDocumentIsRevoked is returned when a document is revoked
	ErrDocumentIsRevoked = NewError("DOCUMENT_IS_REVOKED")
	// ErrNoTransactionID is returned when transactionID is not present
	ErrNoTransactionID = NewError("NO_TRANSACTION_ID")

	// ErrNoDocumentFound is returned when no document is found
	ErrNoDocumentFound = NewError("NO_DOCUMENT_FOUND")

	// ErrDocumentAlreadyExists is returned when a document already exists
	ErrDocumentAlreadyExists = NewError("DOCUMENT_ALREADY_EXISTS")

	// ErrNoDocumentData is returned when no document_data is found
	ErrNoDocumentData = NewError("NO_DOCUMENT_DATA")

	// ErrNoIdentityFound is returned when no identity is found
	ErrNoIdentityFound = NewError("NO_IDENTITY_FOUND")

	// ErrDuplicateKey is returned when a duplicate key is found
	ErrDuplicateKey = NewError("DUPLICATE_KEY")

	// ErrNoRevocationID is returned when no revocation_id is found
	ErrNoRevocationID = NewError("NO_REVOCATION_ID")

	// ErrPrivateKeyMissing error for empty private key
	ErrPrivateKeyMissing = NewError("ERR_PRIVATE_KEY_MISSING")

	// ErrNoKnownDocumentType error for no known document type
	ErrNoKnownDocumentType = NewError("ERR_NO_KNOWN_DOCUMENT_TYPE")

	// ErrInternalServerError error for internal server error
	ErrInternalServerError = NewError("INTERNAL_SERVER_ERROR")
)

// Error is a struct that represents an error
type Error struct {
	Title string `json:"title" `
	Err   any    `json:"details"`
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return fmt.Sprintf("Error: [%s]", e.Title)
	}
	return fmt.Sprintf("Error: [%s] %+v", e.Title, e.Err)
}

// ErrorResponse is a struct that represents an error response in JSON from REST API
type ErrorResponse struct {
	Error *Error `json:"error"`
}

func NewError(title string) *Error {
	return &Error{Title: title}
}

func NewErrorDetails(title string, err any) *Error {
	return &Error{Title: title, Err: err}
}

// NewErrorFromError creates a new Error from an error
func NewErrorFromError(err error) *Error {
	if err == nil {
		return nil
	}

	if jsonUnmarshalTypeError, ok := err.(*json.UnmarshalTypeError); ok {
		return &Error{Title: "json_type_error", Err: formatJSONUnmarshalTypeError(jsonUnmarshalTypeError)}
	}
	if jsonSyntaxError, ok := err.(*json.SyntaxError); ok {
		return &Error{Title: "json_syntax_error", Err: map[string]any{"position": jsonSyntaxError.Offset, "error": jsonSyntaxError.Error()}}
	}
	if validatorErr, ok := err.(validator.ValidationErrors); ok {
		return &Error{Title: "validation_error", Err: formatValidationErrors(validatorErr)}
	}
	if errors.Is(err, mongo.ErrNoDocuments) || errors.Is(err, ErrNoDocumentFound) {
		fmt.Println("Mongo no documents")
		return &Error{Title: "database_error", Err: ErrNoDocumentFound}
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
