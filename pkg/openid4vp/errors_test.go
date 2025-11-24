package openid4vp

import (
	"testing"
)

func TestErrorResponse_Error(t *testing.T) {
	tests := []struct {
		name        string
		errorCode   string
		description string
		state       string
		want        string
	}{
		{
			name:        "error with description",
			errorCode:   ErrorInvalidRequest,
			description: "The request is missing a required parameter",
			state:       "state123",
			want:        "invalid_request: The request is missing a required parameter",
		},
		{
			name:        "error without description",
			errorCode:   ErrorAccessDenied,
			description: "",
			state:       "state456",
			want:        "access_denied",
		},
		{
			name:        "VP formats not supported",
			errorCode:   ErrorVPFormatsNotSupported,
			description: "Only vc+sd-jwt format is supported",
			state:       "",
			want:        "vp_formats_not_supported: Only vc+sd-jwt format is supported",
		},
		{
			name:        "invalid client",
			errorCode:   ErrorInvalidClient,
			description: "Client authentication failed",
			state:       "xyz",
			want:        "invalid_client: Client authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &ErrorResponse{
				ErrorCode:        tt.errorCode,
				ErrorDescription: tt.description,
				State:            tt.state,
			}

			if got := err.Error(); got != tt.want {
				t.Errorf("ErrorResponse.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewErrorResponse(t *testing.T) {
	tests := []struct {
		name        string
		errorCode   string
		description string
		state       string
	}{
		{
			name:        "create error with all fields",
			errorCode:   ErrorInvalidScope,
			description: "The requested scope is invalid",
			state:       "abc123",
		},
		{
			name:        "create error with minimal fields",
			errorCode:   ErrorAccessDenied,
			description: "",
			state:       "",
		},
		{
			name:        "create wallet unavailable error",
			errorCode:   ErrorWalletUnavailable,
			description: "The wallet is temporarily unavailable",
			state:       "temp-state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewErrorResponse(tt.errorCode, tt.description, tt.state)

			if err == nil {
				t.Fatal("NewErrorResponse() returned nil")
			}

			if err.ErrorCode != tt.errorCode {
				t.Errorf("ErrorCode = %v, want %v", err.ErrorCode, tt.errorCode)
			}

			if err.ErrorDescription != tt.description {
				t.Errorf("ErrorDescription = %v, want %v", err.ErrorDescription, tt.description)
			}

			if err.State != tt.state {
				t.Errorf("State = %v, want %v", err.State, tt.state)
			}
		})
	}
}

func TestErrorResponse_IsAuthorizationError(t *testing.T) {
	tests := []struct {
		name      string
		errorCode string
		want      bool
	}{
		{
			name:      "invalid_request is authorization error",
			errorCode: ErrorInvalidRequest,
			want:      true,
		},
		{
			name:      "invalid_scope is authorization error",
			errorCode: ErrorInvalidScope,
			want:      true,
		},
		{
			name:      "access_denied is authorization error",
			errorCode: ErrorAccessDenied,
			want:      true,
		},
		{
			name:      "invalid_client is authorization error",
			errorCode: ErrorInvalidClient,
			want:      true,
		},
		{
			name:      "vp_formats_not_supported is OpenID4VP error",
			errorCode: ErrorVPFormatsNotSupported,
			want:      false,
		},
		{
			name:      "invalid_request_uri_method is OpenID4VP error",
			errorCode: ErrorInvalidRequestURIMethod,
			want:      false,
		},
		{
			name:      "invalid_transaction_data is OpenID4VP error",
			errorCode: ErrorInvalidTransactionData,
			want:      false,
		},
		{
			name:      "wallet_unavailable is OpenID4VP error",
			errorCode: ErrorWalletUnavailable,
			want:      false,
		},
		{
			name:      "unknown error is not authorization error",
			errorCode: "unknown_error",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &ErrorResponse{
				ErrorCode: tt.errorCode,
			}

			if got := err.IsAuthorizationError(); got != tt.want {
				t.Errorf("IsAuthorizationError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrorConstants(t *testing.T) {
	// Verify all error constants are defined
	constants := map[string]string{
		"ErrorInvalidRequest":          ErrorInvalidRequest,
		"ErrorInvalidScope":            ErrorInvalidScope,
		"ErrorInvalidClient":           ErrorInvalidClient,
		"ErrorAccessDenied":            ErrorAccessDenied,
		"ErrorVPFormatsNotSupported":   ErrorVPFormatsNotSupported,
		"ErrorInvalidRequestURIMethod": ErrorInvalidRequestURIMethod,
		"ErrorInvalidTransactionData":  ErrorInvalidTransactionData,
		"ErrorWalletUnavailable":       ErrorWalletUnavailable,
	}

	expectedValues := map[string]string{
		"ErrorInvalidRequest":          "invalid_request",
		"ErrorInvalidScope":            "invalid_scope",
		"ErrorInvalidClient":           "invalid_client",
		"ErrorAccessDenied":            "access_denied",
		"ErrorVPFormatsNotSupported":   "vp_formats_not_supported",
		"ErrorInvalidRequestURIMethod": "invalid_request_uri_method",
		"ErrorInvalidTransactionData":  "invalid_transaction_data",
		"ErrorWalletUnavailable":       "wallet_unavailable",
	}

	for name, constant := range constants {
		expected := expectedValues[name]
		if constant != expected {
			t.Errorf("Constant %s = %v, want %v", name, constant, expected)
		}
	}
}

func TestErrorResponse_ErrorChaining(t *testing.T) {
	// Test that ErrorResponse can be used as error interface
	var err error = &ErrorResponse{
		ErrorCode:        ErrorInvalidRequest,
		ErrorDescription: "Test error",
		State:            "test-state",
	}

	if err == nil {
		t.Error("ErrorResponse should not be nil when assigned to error interface")
	}

	errMsg := err.Error()
	expectedMsg := "invalid_request: Test error"
	if errMsg != expectedMsg {
		t.Errorf("Error message = %v, want %v", errMsg, expectedMsg)
	}
}

func TestErrorResponse_EmptyFields(t *testing.T) {
	tests := []struct {
		name        string
		err         *ErrorResponse
		expectError string
	}{
		{
			name: "only error code",
			err: &ErrorResponse{
				ErrorCode: ErrorAccessDenied,
			},
			expectError: "access_denied",
		},
		{
			name: "error code with empty description",
			err: &ErrorResponse{
				ErrorCode:        ErrorInvalidScope,
				ErrorDescription: "",
			},
			expectError: "invalid_scope",
		},
		{
			name: "all fields empty except code",
			err: &ErrorResponse{
				ErrorCode:        ErrorWalletUnavailable,
				ErrorDescription: "",
				State:            "",
			},
			expectError: "wallet_unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expectError {
				t.Errorf("Error() = %v, want %v", got, tt.expectError)
			}
		})
	}
}
