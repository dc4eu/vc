package openid4vci

// BatchCredentialRequest https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-batch-credential-request
type BatchCredentialRequest struct {
	CredentialRequests []CredentialRequest `json:"credential_requests" validate:"required"`
}

// BatchCredentialResponse https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-batch-credential-response
type BatchCredentialResponse struct {
	// CredentialResponses: REQUIRED. Array that contains Credential Response objects, as defined in Section 7.2, and/or Deferred Credential Response objects, as defined in Section 9.1. Every entry of the array corresponds to the Credential Request object at the same array index in the credential_requests parameter of the Batch Credential Request.
	CredentialResponses []CredentialResponse `json:"credential_responses" validate:"required"`

	// CNonce OPTIONAL. The c_nonce as defined in Section 7.3.
	CNonce string `json:"c_nonce,omitempty"`

	// CNonceExpiresIn OPTIONAL. The c_nonce_expires_in as defined in Section 7.3.
	CNonceExpiresIn int `json:"c_nonce_expires_in,omitempty"`
}
