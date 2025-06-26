package openid4vp

import (
	"encoding/base64"
	"encoding/json"
)

type AuthorizationRequest_v2 struct {
	ResponseURI string `json:"response_uri,omitempty" bson:"response_uri,omitempty" validate:"required"`

	AUD string `json:"aud,omitempty" bson:"aud,omitempty" validate:"required"`

	ISS string `json:"iss,omitempty" bson:"iss,omitempty" validate:"required"`

	ClientIDScheme string `json:"client_id_scheme,omitempty" bson:"client_id_scheme,omitempty" validate:"required,oneof=x509_san_dns x509_san_uri x509_san_email x509_san_ip x509_san_other"`
	//ClientID REQUIRED. Defined in [RFC6749]. This specification defines additional requirements to enable the use of Client Identifier Schemes as described in Section 5.10.

	ClientID string `json:"client_id,omitempty" bson:"client_id,omitempty" validate:"required"`

	ResponseType string `json:"response_type,omitempty" bson:"response_type,omitempty" validate:"required,oneof=vp_token"`

	//ResponseMode OPTIONAL. Defined in [OAuth.Responses]. This parameter is used (through the new Response Mode direct_post) to ask the Wallet to send the response to the Verifier via an HTTPS connection (see Section 8.2 for more details). It is also used to request signing and encrypting (see Section 8.3 for more details). If the parameter is not present, the default value is fragment.
	ResponseMode string `json:"response_mode,omitempty" bson:"response_mode,omitempty" validate:"omitempty,oneof=fragment query direct_post direct_post.jwt"`

	State string `json:"state,omitempty" bson:"state,omitempty" validate:"required,uuid4"`

	// Nonce REQUIRED. Defined in [OpenID.Core]. It is used to securely bind the Verifiable Presentation(s) provided by the Wallet to the particular transaction. See Section 14.1 for details. Values MUST only contain ASCII URL safe characters (uppercase and lowercase letters, decimal digits, hyphen, period, underscore, and tilde).
	Nonce string `json:"nonce,omitempty" bson:"nonce,omitempty" validate:"required,ascii"`

	// PresentationDefinition A string containing a Presentation Definition JSON object. See Section 5.4 for more details.
	PresentationDefinition *PresentationDefinitionParameter `json:"presentation_definition,omitempty" bson:"presentation_definition,omitempty" validate:"required_without=PresentationDefinitionURI DCQLQuery Scope"`
	ClientMetadata         *ClientMetadata                  `json:"client_metadata,omitempty" bson:"client_metadata,omitempty"`
	IAT                    int64                            `json:"iat,omitempty" bson:"iat,omitempty" validate:"required"`
	/////////

	// PresentationDefinitionURI A string containing an HTTPS URL pointing to a resource where a Presentation Definition JSON object can be retrieved. See Section 5.5 for more details. dcql_query:A string containing a JSON-encoded DCQL query as defined in Section 6.
	PresentationDefinitionURI string `json:"presentation_definition_uri,omitempty" bson:"presentation_definition_uri,omitempty" validate:"required_without=PresentationDefinition DCQLQuery Scope"`

	DCQLQuery string `json:"dcql_query,omitempty" bson:"dcql_query,omitempty" validate:"required_without=PresentationDefinition PresentationDefinitionURI Scope"`

	//  OPTIONAL. Defined in [RFC6749]. The Wallet MAY allow Verifiers to request presentation of Verifiable Credentials by utilizing a pre-defined scope value. See Section 5.6 for more details.
	Scope string `json:"scope,omitempty" bson:"scope,omitempty" validate:"required_without=PresentationDefinition PresentationDefinitionURI DCQLQuery"`

	// RequestMethod OPTIONAL. A string determining the HTTP method to be used when the request_uri parameter is included in the same request. Two case-sensitive valid values are defined in this specification: get and post. If request_uri_method value is get, the Wallet MUST send the request to retrieve the Request Object using the HTTP GET method, i.e., as defined in [RFC9101]. If request_uri_method value is post, a supporting Wallet MUST send the request using the HTTP POST method as detailed in Section 5.11. If the request_uri_method parameter is not present, the Wallet MUST process the request_uri parameter as defined in [RFC9101]. Wallets not supporting the post method will send a GET request to the Request URI (default behavior as defined in [RFC9101]). request_uri_method parameter MUST NOT be present if a request_uri parameter is not present.
	RequestURIMethod string `json:"request_uri_method,omitempty" bson:"request_uri_method,omitempty" validate:"omitempty,eq=post"`

	RequestURI string `json:"request_uri,omitempty" bson:"request_uri,omitempty"`

	// TransactionData OPTIONAL. Array of strings, where each string is a base64url encoded JSON object that contains a typed parameter set with details about the transaction that the Verifier is requesting the End-User to authorize. See Section 8.4 for details. The Wallet MUST return an error if a request contains even one unrecognized transaction data type or transaction data not conforming to the respective type definition. In addition to the parameters determined by the type of transaction data, each transaction_data object consists of the following parameters defined by this specification:
	TransactionData []string `json:"transaction_data,omitempty" bson:"transaction_data,omitempty" validate:"omitempty,dive,base64"`
}

type PresentationDefinitionParameter struct {
	// ID The Presentation Definition **MUST** contain an id property. The value of this property **MUST** be a string. The string **SHOULD** provide a unique ID for the desired context. For example, a UUID such as 32f54163-7166-48f1-93d8-f f217bdb0653 could provide an ID that is unique in a global context, while a simple string such as my_presentation_definition_1 could be suitably unique in a local context. The id property **SHOULD** be unique within the Presentation Definition itself, meaning no other id values should exist at any level with the same value.
	ID string `json:"id,omitempty" bson:"id,omitempty" validate:"required"`

	Title string `json:"title,omitempty" bson:"title,omitempty" validate:"omitempty"`

	Description string `json:"description,omitempty" bson:"description,omitempty" validate:"omitempty"`

	// InputDescriptors The Presentation Definition **MUST** contain an input_descriptors property. Its value **MUST** be an array of Input Descriptor Objects, the composition of which are described in the Input Descriptors section below.
	InputDescriptors []InputDescriptor `json:"input_descriptors,omitempty" bson:"input_descriptors,omitempty" validate:"required"`

	// Name The Presentation Definition **MAY** contain a name property. If present, its value **SHOULD** be a human-friendly string intended to constitute a distinctive designation of the Presentation Definition.
	Name string `json:"name,omitempty" bson:"name,omitempty"`

	// Purpose The Presentation Definition **MAY** contain a purpose property. If present, its value **MUST** be a string that describes the purpose for which the Presentation Definition's inputs are being used for.
	Purpose string `json:"purpose,omitempty" bson:"purpose,omitempty"`
}

type ClientMetadata struct {
	//	jwks: OPTIONAL. A JWKS as defined in [RFC7591]. It MAY contain one or more public keys, such as those used by the Wallet as an input to a key agreement that may be used for encryption of the Authorization Response (see Section 8.3), or where the Wallet will require the public key of the Verifier to generate the Verifiable Presentation. This allows the Verifier to pass ephemeral keys specific to this Authorization Request. Public keys included in this parameter MUST NOT be used to verify the signature of signed Authorization Requests.
	JWKS Keys `json:"jwks,omitempty" bson:"jwks,omitempty" validate:"omitempty"`
	//
	// vp_formats: REQUIRED when not available to the Wallet via another mechanism. As defined in Section 11.1.
	VPFormats map[string]map[string][]string `json:"vp_formats,omitempty" bson:"vp_formats,omitempty"`
	// authorization_signed_response_alg: OPTIONAL. As defined in [JARM].
	AuthorizationSignedResponseALG string `json:"authorization_signed_response_alg,omitempty" bson:"authorization_signed_response_alg,omitempty" validate:"omitempty,oneof=RS256 ES256 PS256 EdDSA"`
	// authorization_encrypted_response_alg: OPTIONAL. As defined in [JARM].
	AuthorizationEncryptedResponseALG string `json:"authorization_encrypted_response_alg,omitempty" bson:"authorization_encrypted_response_alg,omitempty" validate:"omitempty,oneof=RSA-OAEP-256 ECDH-ES A128GCMKW A256GCMKW"`
	// authorization_encrypted_response_enc: OPTIONAL. As defined in [JARM].
	AuthorizationEncryptedResponseENC string `json:"authorization_encrypted_response_enc,omitempty" bson:"authorization_encrypted_response_enc,omitempty" validate:"omitempty,oneof=A128CBC-HS256 A256CBC-HS512 A128GCM A256GCM"`
}

type Keys struct {
	Keys []JWK `json:"keys,omitempty" bson:"keys,omitempty" validate:"omitempty,dive"`
}

type JWK struct {
	KTY string `json:"kty,omitempty" bson:"kty,omitempty" validate:"required,oneof=RSA EC OKP"`
	X   string `json:"x,omitempty" bson:"x,omitempty" validate:"omitempty"`
	Y   string `json:"y,omitempty" bson:"y,omitempty" validate:"omitempty"`
	CRV string `json:"crv,omitempty" bson:"crv,omitempty" validate:"omitempty,oneof=P-256 P-384 P-521 Ed25519 Ed448 X25519 X448"`
	N   string `json:"n,omitempty" bson:"n,omitempty" validate:"omitempty"`
	KID string `json:"kid,omitempty" bson:"kid,omitempty" validate:"omitempty"`
	E   string `json:"e,omitempty" bson:"e,omitempty" validate:"omitempty"`
	Use string `json:"use,omitempty" bson:"use,omitempty" validate:"omitempty,oneof=sig enc"`
	Alg string `json:"alg,omitempty" bson:"alg,omitempty"`
}

type TransactionData struct {
	//type: REQUIRED. String that identifies the type of transaction data . This value determines parameters that can be included in the transaction_data object. The specific values are out of scope of this specification. It is RECOMMENDED to use collision-resistant names for type values.
	Type string `json:"type,omitempty" bson:"type,omitempty" validate:"required"`

	// credential_ids: REQUIRED. Array of strings each referencing a Credential requested by the Verifier that can be used to authorize this transaction. In [DIF.PresentationExchange], the string matches the id field in the Input Descriptor. In the Digital Credentials Query Language, the string matches the id field in the Credential Query. If there is more than one element in the array, the Wallet MUST use only one of the referenced Credentials for transaction authorization.
	CredentialIDS []string `json:"credential_ids,omitempty" bson:"credential_ids,omitempty" validate:"required,dive,required"`

	// transaction_data_hashes_alg: OPTIONAL. Array of strings each representing a hash algorithm identifier, one of which MUST be used to calculate hashes in transaction_data_hashes response parameter. The value of the identifier MUST be a hash algorithm value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry [IANA.Hash.Algorithms] or a value defined in another specification and/or profile of this specification. If this parameter is not present, a default value of sha-256 MUST be used. To promote interoperability, implementations MUST support the sha-256 hash algorithm.
	TransactionDataHashesAlg []string `json:"transaction_data_hashes_alg,omitempty" bson:"transaction_data_hashes_alg,omitempty" validate:"omitempty,dive,oneof=sha-256 sha-384 sha-512"`
}

// Base64Encode encodes the TransactionData struct into a base64 URL-encoded string.
func (t *TransactionData) Base64Encode() (string, error) {
	bJSON, err := json.Marshal(t)
	if err != nil {
		return "", err
	}

	encoded := base64.RawURLEncoding.EncodeToString(bJSON)
	if encoded == "" {
		return "", nil
	}

	return encoded, nil
}

