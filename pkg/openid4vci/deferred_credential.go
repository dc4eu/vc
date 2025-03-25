package openid4vci

// DeferredCredentialRequest https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-request
type DeferredCredentialRequest struct {
	TransactionID string `json:"transaction_id" validate:"required"`
}
