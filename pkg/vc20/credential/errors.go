//go:build vc20

package credential

import "errors"

// Validation errors
var (
	ErrMissingContext           = errors.New("@context is required")
	ErrInvalidBaseContext       = errors.New("first @context must be https://www.w3.org/ns/credentials/v2")
	ErrMissingType              = errors.New("type is required")
	ErrMissingVCType            = errors.New("type must include 'VerifiableCredential'")
	ErrMissingIssuer            = errors.New("issuer is required")
	ErrMissingValidFrom         = errors.New("validFrom is required")
	ErrMissingValidUntil        = errors.New("validUntil not specified")
	ErrMissingCredentialSubject = errors.New("credentialSubject is required")
	ErrInvalidIssuerFormat      = errors.New("invalid issuer format")
	ErrInvalidProofFormat       = errors.New("invalid proof format")
	ErrMissingProof             = errors.New("proof is required")
)

// Context errors
var (
	ErrContextNotFound     = errors.New("context document not found")
	ErrContextHashMismatch = errors.New("context hash does not match expected value")
	ErrInvalidContextURL   = errors.New("invalid context URL")
)

// Cryptographic errors
var (
	ErrUnsupportedCryptosuite = errors.New("unsupported cryptographic suite")
	ErrInvalidSignature       = errors.New("invalid signature")
	ErrInvalidProofValue      = errors.New("invalid proof value")
	ErrInvalidKeyFormat       = errors.New("invalid key format")
	ErrSigningFailed          = errors.New("signing failed")
	ErrVerificationFailed     = errors.New("verification failed")
)

// RDF errors
var (
	ErrRDFCanonicalizationFailed = errors.New("RDF canonicalization failed")
	ErrInvalidRDFDataset         = errors.New("invalid RDF dataset")
	ErrBlankNodeRandomization    = errors.New("blank node randomization failed")
)

// Selective disclosure errors
var (
	ErrInvalidJSONPointer = errors.New("invalid JSON pointer")
	ErrMandatoryPointer   = errors.New("mandatory pointer cannot be disclosed selectively")
	ErrInvalidSelection   = errors.New("invalid selection")
	ErrDerivedProofFailed = errors.New("derived proof creation failed")
)
