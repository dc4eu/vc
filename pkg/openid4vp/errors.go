package openid4vp

// ErrorResponse represents an OAuth 2.0 error response as defined in Section 8.5
type ErrorResponse struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	State            string `json:"state,omitempty"`
}

// Error codes defined in OpenID4VP spec Section 8.5
const (
	// OAuth 2.0 standard errors
	ErrorInvalidScope   = "invalid_scope"   // Requested scope value is invalid, unknown, or malformed
	ErrorInvalidRequest = "invalid_request" // Request contains invalid parameters or violates requirements
	ErrorInvalidClient  = "invalid_client"  // Client authentication failed
	ErrorAccessDenied   = "access_denied"   // User denied consent or wallet lacks credentials

	// OpenID4VP specific errors
	ErrorVPFormatsNotSupported   = "vp_formats_not_supported"   // Wallet doesn't support requested VP formats
	ErrorInvalidRequestURIMethod = "invalid_request_uri_method" // Invalid request_uri_method value
	ErrorInvalidTransactionData  = "invalid_transaction_data"   // Transaction data is invalid or malformed
	ErrorWalletUnavailable       = "wallet_unavailable"         // Wallet is unavailable to respond
)

// Error implements the error interface for ErrorResponse
func (e *ErrorResponse) Error() string {
	if e.ErrorDescription != "" {
		return e.ErrorCode + ": " + e.ErrorDescription
	}
	return e.ErrorCode
}

// NewErrorResponse creates a new ErrorResponse
func NewErrorResponse(code, description, state string) *ErrorResponse {
	return &ErrorResponse{
		ErrorCode:        code,
		ErrorDescription: description,
		State:            state,
	}
}

// IsAuthorizationError checks if this is an authorization-related error
func (e *ErrorResponse) IsAuthorizationError() bool {
	return e.ErrorCode == ErrorAccessDenied ||
		e.ErrorCode == ErrorInvalidScope ||
		e.ErrorCode == ErrorInvalidRequest ||
		e.ErrorCode == ErrorInvalidClient
}
