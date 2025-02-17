package openid4vci

// DeferredCredentialRequest https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-request
type DeferredCredentialRequest struct {
	TransactionID string `json:"transaction_id" validate:"required"`
}

// DeferredCredentialResponse https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-respons
type DeferredCredentialResponse struct {
	Credentials    []map[string]string `json:"credentials,omitempty" validate:"required_without=TransactionID,required_without=NotificationID"`
	NotificationID string              `json:"notification_id,omitempty" validate:"required_with=Credentials"`
}
