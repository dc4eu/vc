package openid4vci

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"vc/internal/gen/issuer/apiv1_issuer"

	"github.com/golang-jwt/jwt/v5"
)

//{"body": "{\"format\":\"vc+sd-jwt\",\
//"proof\":{\"proof_type\":\"jwt\",
// \"jwt\":\"eyJhbGciOiJFUzI1NiIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiandrIjp7ImNydiI6IlAtMjU2IiwiZXh0Ijp0cnVlLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJrdHkiOiJFQyIsIngiOiJLYURFejhybkt3RGVHeXB6RlNwclRxX3BLZjNLLXFZdzU2dW4xSjcyYkZRIiwieSI6IkFNV0d2Umo3QU9Zc3dGNU5BSU55Rnk3OUdUVjJOR1ktcG5PM0JKZHpwMDAifX0.eyJub25jZSI6IiIsImF1ZCI6Imh0dHBzOi8vdmMtaW50ZXJvcC0zLnN1bmV0LnNlIiwiaXNzIjoiMTAwMyIsImlhdCI6MTc0ODUzNTQ3OH0.hlZrNbnzD8eR7Ulmp6qv4A4Ev-GLvhUgZ4P3ZURSd1C7OVFhhzgiPoAW41TYMcgFPuuwNsftebBUEncC4mWcKA\"},\
//"vct\":\"DiplomaCredential\"}"}

type CredentialRequestHeader struct {
	DPoP          string `header:"dpop" validate:"required"`
	Authorization string `header:"Authorization" validate:"required"`
}

// HashAuthorizeToken hashes the Authorization header using SHA-256 and encodes it in Base64 URL format.
func (c *CredentialRequestHeader) HashAuthorizeToken() string {
	token := strings.TrimPrefix(c.Authorization, "DPoP ")
	fmt.Println("Token: ", token)

	tokenS256 := sha256.Sum256([]byte(token))
	fmt.Printf("Token SHA256: %x\n", tokenS256)

	b64 := base64.RawURLEncoding.EncodeToString(tokenS256[:])
	fmt.Println("Base64 Raw Encoded Token SHA256: ", b64)
	return b64
}

// CredentialRequest https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request
type CredentialRequest struct {
	Headers *CredentialRequestHeader

	// Format REQUIRED when the credential_identifiers parameter was not returned from the Token Response. It MUST NOT be used otherwise. It is a String that determines the format of the Credential to be issued, which may determine the type and any other information related to the Credential to be issued. Credential Format Profiles consist of the Credential format specific parameters that are defined in Appendix A. When this parameter is used, the credential_identifier Credential Request parameter MUST NOT be present.
	Format string `json:"format"`

	// Proof OPTIONAL. Object containing the proof of possession of the cryptographic key material the issued Credential would be bound to. The proof object is REQUIRED if the proof_types_supported parameter is non-empty and present in the credential_configurations_supported parameter of the Issuer metadata for the requested Credential. The proof object MUST contain the following:
	Proof *Proof `json:"proof"`

	// REQUIRED when credential_identifiers parameter was returned from the Token Response. It MUST NOT be used otherwise. It is a String that identifies a Credential that is being requested to be issued. When this parameter is used, the format parameter and any other Credential format specific parameters such as those defined in Appendix A MUST NOT be present.
	CredentialIdentifier string `json:"credential_identifier"`

	// CredentialIdentifier REQUIRED when credential_identifiers parameter was returned from the Token Response. It MUST NOT be used otherwise. It is a String that identifies a Credential that is being requested to be issued. When this parameter is used, the format parameter and any other Credential format specific parameters such as those defined in Appendix A MUST NOT be present.
	CredentialResponseEncryption *CredentialResponseEncryption `json:"credential_response_encryption"`

	//VCT string `json:"vct" validate:"required"`
}

// IsAccessTokenDPoP checks if the Authorize header belong to DPoP proof
func (c *CredentialRequestHeader) IsAccessTokenDPoP() bool {

	return false
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
	// Credentials OPTIONAL. Contains an array of issued Credentials. It MUST NOT be used if credential or transaction_id parameter is present. The values in the array MAY be a string or an object, depending on the Credential Format. See Appendix A for the Credential Format-specific encoding requirements.
	Credentials []Credential `json:"credentials,omitempty" validate:"required_without=TransactionID Credential"`

	// TransactionID: OPTIONAL. String identifying a Deferred Issuance transaction. This claim is contained in the response if the Credential Issuer was unable to immediately issue the Credential. The value is subsequently used to obtain the respective Credential with the Deferred Credential Endpoint (see Section 9). It MUST be present when the credential parameter is not returned. It MUST be invalidated after the Credential for which it was meant has been obtained by the Wallet.
	TransactionID string `json:"transaction_id,omitempty" validate:"required_without=Credentials Credential"`

	// CNonce: OPTIONAL. String containing a nonce to be used to create a proof of possession of key material when requesting a Credential (see Section 7.2). When received, the Wallet MUST use this nonce value for its subsequent Credential Requests until the Credential Issuer provides a fresh nonce.
	CNonce string `json:"c_nonce,omitempty"`

	// CNonceExpiresIn: OPTIONAL. Number denoting the lifetime in seconds of the c_nonce.
	CNonceExpiresIn int `json:"c_nonce_expires_in,omitempty"`

	//NotificationID: OPTIONAL. String identifying an issued Credential that the Wallet includes in the Notification Request as defined in Section 10.1. This parameter MUST NOT be present if credential parameter is not present.
	NotificationID string `json:"notification_id,omitempty" validate:"required_with=Credentials"`
}

type Credential struct {
	Credential string `json:"credential" validate:"required"`
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

func (p *Proof) ExtractJWK() (*apiv1_issuer.Jwk, error) {
	if p.JWT == "" {
		return nil, fmt.Errorf("JWT is empty")
	}

	headerBase64 := strings.Split(p.JWT, ".")[0]

	headerByte, err := base64.RawStdEncoding.DecodeString(headerBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	headerMap := map[string]any{}
	if err := json.Unmarshal(headerByte, &headerMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT header: %w", err)
	}

	jwkMap, ok := headerMap["jwk"]
	if !ok {
		return nil, fmt.Errorf("jwk not found in JWT header")
	}

	jwkByte, err := json.Marshal(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK: %w", err)
	}

	jwk := &apiv1_issuer.Jwk{}
	if err := json.Unmarshal(jwkByte, jwk); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWK: %w", err)
	}

	return jwk, nil
}

// CredentialResponseEncryption holds the JWK for encryption
type CredentialResponseEncryption struct {
	JWK JWK    `json:"jwk" validate:"required"`
	Alg string `json:"alg" validate:"required"`
	Enc string `json:"enc" validate:"required"`
}
