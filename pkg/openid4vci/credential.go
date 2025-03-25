package openid4vci

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// CredentialRequest https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request
type CredentialRequest struct {
	// Format REQUIRED when the credential_identifiers parameter was not returned from the Token Response. It MUST NOT be used otherwise. It is a String that determines the format of the Credential to be issued, which may determine the type and any other information related to the Credential to be issued. Credential Format Profiles consist of the Credential format specific parameters that are defined in Appendix A. When this parameter is used, the credential_identifier Credential Request parameter MUST NOT be present.
	Format string `json:"format"`

	// credential_definition

	// Proof OPTIONAL. Object containing the proof of possession of the cryptographic key material the issued Credential would be bound to. The proof object is REQUIRED if the proof_types_supported parameter is non-empty and present in the credential_configurations_supported parameter of the Issuer metadata for the requested Credential. The proof object MUST contain the following:
	Proof *Proof `json:"proof"`

	// REQUIRED when credential_identifiers parameter was returned from the Token Response. It MUST NOT be used otherwise. It is a String that identifies a Credential that is being requested to be issued. When this parameter is used, the format parameter and any other Credential format specific parameters such as those defined in Appendix A MUST NOT be present.
	CredentialIdentifier string `json:"credential_identifier"`

	// CredentialIdentifier REQUIRED when credential_identifiers parameter was returned from the Token Response. It MUST NOT be used otherwise. It is a String that identifies a Credential that is being requested to be issued. When this parameter is used, the format parameter and any other Credential format specific parameters such as those defined in Appendix A MUST NOT be present.
	CredentialResponseEncryption *CredentialResponseEncryption `json:"credential_response_encryption"`
}

// Validate validates the CredentialRequest based claims in TokenResponse
func (c *CredentialRequest) Validate(ctx context.Context, tokenResponse *TokenResponse) error {
	for _, authorizationDetails := range tokenResponse.AuthorizationDetails {
		fmt.Println("AuthorizationDetails: ", authorizationDetails)
	}

	return nil
}

// CredentialResponse https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response
type CredentialResponse struct {
	//Credential: OPTIONAL. Contains issued Credential. It MUST be present when transaction_id is not returned. It MAY be a string or an object, depending on the Credential format. See Appendix A for the Credential format specific encoding requirements.
	Credential any `json:"credential,omitempty" validate:"required_without=TransactionID,required_without=NotificationID Credentials"`

	// Credentials OPTIONAL. Contains an array of issued Credentials. It MUST NOT be used if credential or transaction_id parameter is present. The values in the array MAY be a string or an object, depending on the Credential Format. See Appendix A for the Credential Format-specific encoding requirements.
	Credentials []any `json:"credentials,omitempty" validate:"required_without=TransactionID Credential"`

	// TransactionID: OPTIONAL. String identifying a Deferred Issuance transaction. This claim is contained in the response if the Credential Issuer was unable to immediately issue the Credential. The value is subsequently used to obtain the respective Credential with the Deferred Credential Endpoint (see Section 9). It MUST be present when the credential parameter is not returned. It MUST be invalidated after the Credential for which it was meant has been obtained by the Wallet.
	TransactionID string `json:"transaction_id,omitempty" validate:"required_without=Credentials Credential"`

	// CNonce: OPTIONAL. String containing a nonce to be used to create a proof of possession of key material when requesting a Credential (see Section 7.2). When received, the Wallet MUST use this nonce value for its subsequent Credential Requests until the Credential Issuer provides a fresh nonce.
	CNonce string `json:"c_nonce,omitempty"`

	// CNonceExpiresIn: OPTIONAL. Number denoting the lifetime in seconds of the c_nonce.
	CNonceExpiresIn int `json:"c_nonce_expires_in,omitempty"`

	//NotificationID: OPTIONAL. String identifying an issued Credential that the Wallet includes in the Notification Request as defined in Section 10.1. This parameter MUST NOT be present if credential parameter is not present.
	NotificationID string `json:"notification_id,omitempty" validate:"required_with=Credentials"`
}

// ProofJWT holds the JWT for proof
type ProofJWT struct {
	jwt.RegisteredClaims
}

// JWK holds the JSON Web Key
type JWK struct {
	CRV string `json:"crv" validate:"required"`
	KID string `json:"kid" validate:"required"`
	KTY string `json:"kty" validate:"required"`
	X   string `json:"x" validate:"required"`
	Y   string `json:"y" validate:"required"`
	D   string `json:"d" validate:"required"`
}

// Proof https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request
type Proof struct {
	// ProofType REQUIRED. String denoting the key proof type. The value of this parameter determines other parameters in the key proof object and its respective processing rules. Key proof types defined in this specification can be found in Section 7.2.1.
	ProofType string `json:"proof_type" validate:"required,oneof=jwt ldp_vp cwt"`

	JWT         string `json:"jwt,omitempty"`
	LDPVP       string `json:"ldp_vp,omitempty"`
	Attestation string `json:"attestation"`
}

// CredentialResponseEncryption holds the JWK for encryption
type CredentialResponseEncryption struct {
	JWK JWK    `json:"jwk" validate:"required"`
	Alg string `json:"alg" validate:"required"`
	Enc string `json:"enc" validate:"required"`
}
