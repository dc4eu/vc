package openid4vp

type DCQL struct {
	// Credentials REQUIRED. A non-empty array of Credential Queries as defined in Section 6.1 that specify the requested Credentials.
	Credentials []CredentialQuery `json:"credentials" validate:"required,min=1,dive,required"`

	// CredentialSets OPTIONAL. A non-empty array of Credential Set Queries as defined in Section 6.2 that specifies additional constraints on which of the requested Credentials to return.
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty" validate:"omitempty,min=1,dive,required"`
}

// CredentialQuery is an object representing a request for a presentation of one or more matching Credentials.
type CredentialQuery struct {
	//ID REQUIRED. A string identifying the Credential in the response and, if provided, the constraints in credential_sets. The value MUST be a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-) characters. Within the Authorization Request, the same id MUST NOT be present more than once.
	ID string `json:"id" validate:"required"`

	// Format REQUIRED. A string that specifies the format of the requested Credential. Valid Credential Format Identifier values are defined in Appendix B.
	Format string `json:"format" validate:"required"`

	// Multiple OPTIONAL. A boolean which indicates whether multiple Credentials can be returned for this Credential Query. If omitted, the default value is false.
	Multiple bool `json:"multiple,omitempty"`

	// Meta REQUIRED. An object defining additional properties requested by the Verifier that apply to the metadata and validity data of the Credential. The properties of this object are defined per Credential Format. Examples of those are in Appendix B.3.5 and Appendix B.2.3. If empty, no specific constraints are placed on the metadata or validity of the requested Credential.
	Meta MetaQuery `json:"meta" validate:"required"`

	// TrustedAuthorities OPTIONAL. A non-empty array of objects as defined in Section 6.1.1 that specifies expected authorities or trust frameworks that certify Issuers, that the Verifier will accept. Every Credential returned by the Wallet SHOULD match at least one of the conditions present in the corresponding trusted_authorities array if present.
	TrustedAuthorities []TrustedAuthority `json:"trusted_authorities,omitempty"`

	// RequireCryptographicHolderBinding OPTIONAL. A boolean which indicates whether the Verifier requires a Cryptographic Holder Binding proof. The default value is true, i.e., a Verifiable Presentation with Cryptographic Holder Binding is required. If set to false, the Verifier accepts a Credential without Cryptographic Holder Binding proof.
	RequireCryptographicHolderBinding bool `json:"require_cryptographic_holder_binding,omitempty"`

	// Claims OPTIONAL. A non-empty array of objects as defined in Section 6.3 that specifies claims in the requested Credential. Verifiers MUST NOT point to the same claim more than once in a single query. Wallets SHOULD ignore such duplicate claim queries.
	Claims []ClaimQuery `json:"claims,omitempty"`

	// ClaimSet OPTIONAL. A non-empty array containing arrays of identifiers for elements in claims that specifies which combinations of claims for the Credential are requested. The rules for selecting claims to send are defined in Section 6.4.1.
	ClaimSet []string `json:"claim_sets,omitempty" validate:"omitempty,min=1,dive,required"`
}

type CredentialSetQuery struct {
	// Options REQUIRED A non-empty array, where each value in the array is a list of Credential Query identifiers representing one set of Credentials that satisfies the use case. The value of each element in the options array is a non-empty array of identifiers which reference elements in credentials.
	Options [][]string `json:"options" validate:"required,min=1,dive,required,min=1,dive,required"`

	// Required OPTIONAL A boolean which indicates whether this set of Credentials is required to satisfy the particular use case at the Verifier. If omitted, the default value is true.
	Required bool `json:"required,omitempty"`

	// Purpose Can't find in spec, but in example from wwwallet
	Purpose string `json:"purpose,omitempty"`
}

type MetaQuery struct {
	// VCTValues REQUIRED. A non-empty array of strings that specifies allowed values for the type of the requested Verifiable Credential. All elements in the array MUST be valid type identifiers as defined in [I-D.ietf-oauth-sd-jwt-vc]. The Wallet MAY return Credentials that inherit from any of the specified types, following the inheritance logic defined in [I-D.ietf-oauth-sd-jwt-vc].
	VCTValues []string `json:"vct_values" yaml:"vct_values" validate:"required,min=1,dive,required"`
}

type TrustedAuthority struct {
	// REQUIRED. A string uniquely identifying the type of information about the issuer trust framework. Types defined by this specification are listed below.
	Type string `json:"type" validate:"required,oneof=aki etsi_tl openid_federation"`

	// REQUIRED. A non-empty array of strings, where each string (value) contains information specific to the used Trusted Authorities Query type that allows the identification of an issuer, a trust framework, or a federation that an issuer belongs to.
	Values []string `json:"values" validate:"required,min=1"`
}

type ClaimQuery struct {
	// Path REQUIRED The value MUST be a non-empty array representing a claims path pointer that specifies the path to a claim within the Credential, as defined in Section 7.
	Path []string `json:"path" validate:"required,min=1,dive,required"`
}

//type ClaimQuery struct {
//	// ID REQUIRED if claim_sets is present in the Credential Query; OPTIONAL otherwise. A string identifying the particular claim. The value MUST be a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-) characters. Within the particular claims array, the same id MUST NOT be present more than once.
//	ID string `json:"id,omitempty" validate:"omitempty,alphanumunicode"`
//
//	// Path REQUIRED The value MUST be a non-empty array representing a claims path pointer that specifies the path to a claim within the Credential, as defined in Section 7.
//	Path []string `json:"path" validate:"required,min=1,dive,required"`
//
//	// Values OPTIONAL A non-empty array of strings, integers or boolean values that specifies the expected values of the claim. If the values property is present, the Wallet SHOULD return the claim only if the type and value of the claim both match exactly for at least one of the elements in the array. Details of the processing rules are defined in Section 6.4.1.
//	Values []any `json:"values,omitempty" validate:"omitempty,min=1,dive,required"`
//}
