//go:build vc20

package credential

import (
	"encoding/json"
	"time"
)

// VerifiableCredential represents a W3C Verifiable Credentials Data Model v2.0 credential
// See: https://www.w3.org/TR/vc-data-model-2.0/
type VerifiableCredential struct {
	// @context is REQUIRED and MUST be one or more URIs
	// First context MUST be https://www.w3.org/ns/credentials/v2
	Context []string `json:"@context"`

	// ID is OPTIONAL identifier for the credential
	ID string `json:"id,omitempty"`

	// Type is REQUIRED and MUST include "VerifiableCredential"
	Type []string `json:"type"`

	// Issuer is REQUIRED and identifies the issuer
	Issuer interface{} `json:"issuer"` // Can be string (URI) or object with id

	// ValidFrom is REQUIRED in VC 2.0 (replaces issuanceDate from VC 1.1)
	ValidFrom string `json:"validFrom"`

	// ValidUntil is OPTIONAL expiration date
	ValidUntil string `json:"validUntil,omitempty"`

	// CredentialSubject is REQUIRED and contains claims about the subject
	CredentialSubject interface{} `json:"credentialSubject"`

	// CredentialStatus is OPTIONAL and describes the status of the credential
	CredentialStatus *CredentialStatus `json:"credentialStatus,omitempty"`

	// CredentialSchema is OPTIONAL and describes the schema of the credential
	CredentialSchema *CredentialSchema `json:"credentialSchema,omitempty"`

	// RefreshService is OPTIONAL and describes how to refresh the credential
	RefreshService *RefreshService `json:"refreshService,omitempty"`

	// TermsOfUse is OPTIONAL and describes the terms of use
	TermsOfUse []interface{} `json:"termsOfUse,omitempty"`

	// Evidence is OPTIONAL and provides evidence for the claims
	Evidence []interface{} `json:"evidence,omitempty"`

	// Proof contains the cryptographic proof(s)
	// Can be a single proof or array of proofs
	Proof interface{} `json:"proof,omitempty"`
}

// CredentialStatus describes the status of a credential
type CredentialStatus struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	StatusPurpose   string `json:"statusPurpose,omitempty"`
	StatusListIndex string `json:"statusListIndex,omitempty"`
	StatusListCredential string `json:"statusListCredential,omitempty"`
}

// CredentialSchema describes the schema of a credential
type CredentialSchema struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// RefreshService describes how to refresh a credential
type RefreshService struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// VerifiablePresentation represents a W3C Verifiable Presentation
type VerifiablePresentation struct {
	// @context is REQUIRED
	Context []string `json:"@context"`

	// ID is OPTIONAL identifier for the presentation
	ID string `json:"id,omitempty"`

	// Type is REQUIRED and MUST include "VerifiablePresentation"
	Type []string `json:"type"`

	// Holder is OPTIONAL and identifies the holder
	Holder string `json:"holder,omitempty"`

	// VerifiableCredential contains one or more verifiable credentials
	VerifiableCredential []interface{} `json:"verifiableCredential,omitempty"`

	// Proof contains the cryptographic proof(s)
	Proof interface{} `json:"proof,omitempty"`
}

// DataIntegrityProof represents a Data Integrity proof
// See: https://www.w3.org/TR/vc-data-integrity/
type DataIntegrityProof struct {
	// Type identifies the cryptographic suite (e.g., "DataIntegrityProof")
	Type string `json:"type"`

	// CryptographicSuite identifies the specific suite (e.g., "ecdsa-sd-2023")
	Cryptosuite string `json:"cryptosuite"`

	// Created is the timestamp when the proof was created
	Created string `json:"created"`

	// VerificationMethod identifies the key used to create the proof
	VerificationMethod string `json:"verificationMethod"`

	// ProofPurpose describes the purpose of the proof
	ProofPurpose string `json:"proofPurpose"`

	// ProofValue is the encoded proof value
	ProofValue string `json:"proofValue"`

	// PreviousProof is OPTIONAL reference to a previous proof
	PreviousProof string `json:"previousProof,omitempty"`

	// Nonce is OPTIONAL for replay protection
	Nonce string `json:"nonce,omitempty"`
}

// IssuerInfo represents detailed issuer information
type IssuerInfo struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// Constants for W3C VC 2.0
const (
	// Base context URL for VC 2.0
	VC20ContextURL = "https://www.w3.org/ns/credentials/v2"

	// Base context SHA-256 hash for integrity verification
	VC20ContextHash = "59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734"

	// Media types
	MediaTypeVC = "application/vc"
	MediaTypeVP = "application/vp"

	// Credential types
	TypeVerifiableCredential     = "VerifiableCredential"
	TypeVerifiablePresentation   = "VerifiablePresentation"

	// Proof types
	ProofTypeDataIntegrity = "DataIntegrityProof"

	// Cryptosuites
	CryptosuiteECDSASD2023   = "ecdsa-sd-2023"
	CryptosuiteECDSARDFC2019 = "ecdsa-rdfc-2019"
	CryptosuiteECDSAJCS2019  = "ecdsa-jcs-2019"

	// Proof purposes
	ProofPurposeAuthentication  = "authentication"
	ProofPurposeAssertion       = "assertionMethod"
	ProofPurposeKeyAgreement    = "keyAgreement"
	ProofPurposeCapabilityInvocation = "capabilityInvocation"
	ProofPurposeCapabilityDelegation = "capabilityDelegation"
)

// Validate performs basic validation on the credential
func (vc *VerifiableCredential) Validate() error {
	if len(vc.Context) == 0 {
		return ErrMissingContext
	}
	if vc.Context[0] != VC20ContextURL {
		return ErrInvalidBaseContext
	}
	if len(vc.Type) == 0 {
		return ErrMissingType
	}
	hasVCType := false
	for _, t := range vc.Type {
		if t == TypeVerifiableCredential {
			hasVCType = true
			break
		}
	}
	if !hasVCType {
		return ErrMissingVCType
	}
	if vc.Issuer == nil {
		return ErrMissingIssuer
	}
	if vc.ValidFrom == "" {
		return ErrMissingValidFrom
	}
	if vc.CredentialSubject == nil {
		return ErrMissingCredentialSubject
	}
	return nil
}

// GetIssuerID extracts the issuer ID from the issuer field
func (vc *VerifiableCredential) GetIssuerID() (string, error) {
	switch v := vc.Issuer.(type) {
	case string:
		return v, nil
	case map[string]interface{}:
		if id, ok := v["id"].(string); ok {
			return id, nil
		}
		return "", ErrInvalidIssuerFormat
	default:
		return "", ErrInvalidIssuerFormat
	}
}

// ToJSON marshals the credential to JSON
func (vc *VerifiableCredential) ToJSON() ([]byte, error) {
	return json.Marshal(vc)
}

// FromJSON unmarshals a credential from JSON
func FromJSON(data []byte) (*VerifiableCredential, error) {
	var vc VerifiableCredential
	if err := json.Unmarshal(data, &vc); err != nil {
		return nil, err
	}
	return &vc, nil
}

// ParseValidFrom parses the validFrom field as time.Time
func (vc *VerifiableCredential) ParseValidFrom() (time.Time, error) {
	return time.Parse(time.RFC3339, vc.ValidFrom)
}

// ParseValidUntil parses the validUntil field as time.Time
func (vc *VerifiableCredential) ParseValidUntil() (time.Time, error) {
	if vc.ValidUntil == "" {
		return time.Time{}, ErrMissingValidUntil
	}
	return time.Parse(time.RFC3339, vc.ValidUntil)
}

// IsExpired checks if the credential has expired
func (vc *VerifiableCredential) IsExpired() bool {
	if vc.ValidUntil == "" {
		return false // No expiration
	}
	validUntil, err := vc.ParseValidUntil()
	if err != nil {
		return true // Parse error, treat as expired for safety
	}
	return time.Now().After(validUntil)
}

// IsValidNow checks if the credential is valid at the current time
func (vc *VerifiableCredential) IsValidNow() bool {
	validFrom, err := vc.ParseValidFrom()
	if err != nil {
		return false
	}
	if time.Now().Before(validFrom) {
		return false // Not yet valid
	}
	return !vc.IsExpired()
}
