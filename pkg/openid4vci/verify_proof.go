package openid4vci

import (
	"crypto"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// VerifyProofOptions contains optional parameters for proof verification
type VerifyProofOptions struct {
	// CNonce is the server-provided nonce value that must match the nonce in the proof
	// Required when the Credential Issuer has a Nonce Endpoint
	CNonce string
	// Audience is the expected Credential Issuer Identifier (required for aud validation)
	Audience string
	// SupportedAlgorithms is a list of supported signing algorithms
	SupportedAlgorithms []string
}

// verifyJWTProof verifies a JWT proof according to OpenID4VCI 1.0 Appendix F.1
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type
func verifyJWTProof(jwt string, publicKey crypto.PublicKey, opts *VerifyProofOptions) error {
	claims := jwtv5.MapClaims{}

	token, err := jwtv5.ParseWithClaims(jwt, claims, func(token *jwtv5.Token) (any, error) {
		// Validate JOSE header requirements

		// alg: REQUIRED - must be a registered asymmetric digital signature algorithm, not "none"
		alg, ok := token.Header["alg"]
		if !ok {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "alg parameter not found in header"}
		}
		algStr, ok := alg.(string)
		if !ok || algStr == "" {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "alg parameter is invalid"}
		}
		if algStr == "none" {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "alg parameter value 'none' is not allowed"}
		}

		// Check if algorithm is supported (if supported algorithms are specified)
		if opts != nil && len(opts.SupportedAlgorithms) > 0 {
			if !slices.Contains(opts.SupportedAlgorithms, algStr) {
				return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("alg '%s' is not supported", algStr)}
			}
		}

		// typ: REQUIRED - must be "openid4vci-proof+jwt"
		typ, ok := token.Header["typ"]
		if !ok {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "typ parameter not found in header"}
		}
		if typ != "openid4vci-proof+jwt" {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "typ parameter value must be 'openid4vci-proof+jwt'"}
		}

		// Validate key binding - exactly one of kid, jwk, or x5c must be present
		hasKid := token.Header["kid"] != nil
		hasJwk := token.Header["jwk"] != nil
		hasX5c := token.Header["x5c"] != nil

		keyBindingCount := 0
		if hasKid {
			keyBindingCount++
		}
		if hasJwk {
			keyBindingCount++
		}
		if hasX5c {
			keyBindingCount++
		}

		if keyBindingCount == 0 {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "one of kid, jwk, or x5c must be present in header"}
		}

		// kid MUST NOT be present if jwk or x5c is present
		if hasJwk && hasKid {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "kid must not be present when jwk is present"}
		}
		if hasX5c && hasKid {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "kid must not be present when x5c is present"}
		}
		if hasJwk && hasX5c {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "jwk and x5c must not both be present"}
		}

		// Validate that jwk does not contain a private key (d parameter)
		if hasJwk {
			jwkMap, ok := token.Header["jwk"].(map[string]any)
			if ok {
				if _, hasD := jwkMap["d"]; hasD {
					return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "jwk must not contain private key material (d parameter)"}
				}
			}
		}

		// Validate JWT body claims

		// aud: REQUIRED - must be the Credential Issuer Identifier
		if _, ok := claims["aud"]; !ok {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "aud claim not found in JWT body"}
		}
		if opts != nil && opts.Audience != "" {
			aud, err := claims.GetAudience()
			if err != nil {
				return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "failed to parse aud claim"}
			}
			if !slices.Contains(aud, opts.Audience) {
				return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "aud claim does not match expected audience"}
			}
		}

		// iat: REQUIRED - issuance time
		if _, ok := claims["iat"]; !ok {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "iat claim not found in JWT body"}
		}
		t, err := claims.GetIssuedAt()
		if err != nil {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "failed to parse iat claim"}
		}
		if t.After(time.Now()) {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "iat claim value is in the future"}
		}

		// nonce: OPTIONAL but REQUIRED when issuer has Nonce Endpoint
		if opts != nil && opts.CNonce != "" {
			nonce, ok := claims["nonce"]
			if !ok {
				return nil, &Error{Err: ErrInvalidNonce, ErrorDescription: "nonce claim not found but c_nonce was provided"}
			}
			if nonce != opts.CNonce {
				return nil, &Error{Err: ErrInvalidNonce, ErrorDescription: "nonce claim does not match server-provided c_nonce"}
			}
		}

		// Validate signing method - must be asymmetric algorithm
		switch token.Method.(type) {
		case *jwtv5.SigningMethodECDSA:
			// ES256, ES384, ES512
		case *jwtv5.SigningMethodRSA:
			// RS256, RS384, RS512
		case *jwtv5.SigningMethodRSAPSS:
			// PS256, PS384, PS512
		case *jwtv5.SigningMethodEd25519:
			// EdDSA
		default:
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("unsupported signing method: %v", algStr)}
		}

		return publicKey, nil
	})

	if err != nil {
		return err
	}

	if !token.Valid {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "JWT signature is invalid"}
	}

	return nil
}

// verifyDIVPProof verifies a Data Integrity Verifiable Presentation proof
// according to OpenID4VCI 1.0 Appendix F.2
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-di_vp-proof-type
func verifyDIVPProof(divp any, opts *VerifyProofOptions) error {
	// Convert to map for validation
	var vpMap map[string]any
	switch v := divp.(type) {
	case map[string]any:
		vpMap = v
	case string:
		if err := json.Unmarshal([]byte(v), &vpMap); err != nil {
			return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "di_vp is not valid JSON"}
		}
	default:
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "di_vp must be a JSON object"}
	}

	// Validate @context - REQUIRED per W3C VC Data Model
	if _, ok := vpMap["@context"]; !ok {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "@context is required in di_vp"}
	}

	// Validate type - REQUIRED, must include "VerifiablePresentation"
	typeVal, ok := vpMap["type"]
	if !ok {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "type is required in di_vp"}
	}
	typeArr, ok := typeVal.([]any)
	if !ok {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "type must be an array in di_vp"}
	}
	if !slices.Contains(typeArr, "VerifiablePresentation") {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "type must include 'VerifiablePresentation'"}
	}

	// Validate proof - REQUIRED, must be a Data Integrity Proof
	proofVal, ok := vpMap["proof"]
	if !ok {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "proof is required in di_vp"}
	}

	// proof can be a single object or an array
	var proofs []map[string]any
	switch p := proofVal.(type) {
	case map[string]any:
		proofs = []map[string]any{p}
	case []any:
		for _, item := range p {
			if pMap, ok := item.(map[string]any); ok {
				proofs = append(proofs, pMap)
			}
		}
	}

	if len(proofs) == 0 {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "proof must contain at least one Data Integrity Proof"}
	}

	for _, proof := range proofs {
		// proofPurpose: REQUIRED, must be "authentication"
		proofPurpose, ok := proof["proofPurpose"]
		if !ok {
			return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "proofPurpose is required in proof"}
		}
		if proofPurpose != "authentication" {
			return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "proofPurpose must be 'authentication'"}
		}

		// domain: REQUIRED, must be the Credential Issuer Identifier
		domain, ok := proof["domain"]
		if !ok {
			return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "domain is required in proof"}
		}
		if opts != nil && opts.Audience != "" {
			if domain != opts.Audience {
				return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "domain does not match expected Credential Issuer Identifier"}
			}
		}

		// challenge: REQUIRED when c_nonce is provided
		if opts != nil && opts.CNonce != "" {
			challenge, ok := proof["challenge"]
			if !ok {
				return &Error{Err: ErrInvalidNonce, ErrorDescription: "challenge is required in proof when c_nonce is provided"}
			}
			if challenge != opts.CNonce {
				return &Error{Err: ErrInvalidNonce, ErrorDescription: "challenge does not match server-provided c_nonce"}
			}
		}

		// cryptosuite: REQUIRED
		if _, ok := proof["cryptosuite"]; !ok {
			return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "cryptosuite is required in proof"}
		}

		// verificationMethod: REQUIRED
		if _, ok := proof["verificationMethod"]; !ok {
			return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "verificationMethod is required in proof"}
		}
	}

	// TODO: Implement actual cryptographic verification of the Data Integrity Proof
	// This requires implementing the specific cryptosuite verification logic

	return nil
}

// verifyAttestationProof verifies a key attestation proof
// according to OpenID4VCI 1.0 Appendix F.3 and Appendix D.1
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-attestation-proof-type
func verifyAttestationProof(attestation string, opts *VerifyProofOptions) error {
	// Parse the key attestation JWT without verifying signature yet
	// (we need to extract claims to validate structure first)
	token, _, err := jwtv5.NewParser().ParseUnverified(attestation, jwtv5.MapClaims{})
	if err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "failed to parse attestation JWT"}
	}

	claims, ok := token.Claims.(jwtv5.MapClaims)
	if !ok {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "failed to extract claims from attestation JWT"}
	}

	// Validate JOSE header

	// alg: REQUIRED, must not be "none"
	alg, ok := token.Header["alg"]
	if !ok {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "alg parameter not found in attestation header"}
	}
	algStr, ok := alg.(string)
	if !ok || algStr == "" || algStr == "none" {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "alg parameter must be a valid asymmetric algorithm, not 'none'"}
	}

	// typ: REQUIRED, must be "key-attestation+jwt"
	typ, ok := token.Header["typ"]
	if !ok {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "typ parameter not found in attestation header"}
	}
	if typ != "key-attestation+jwt" {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "typ parameter must be 'key-attestation+jwt'"}
	}

	// Validate JWT body claims

	// iat: REQUIRED
	if _, ok := claims["iat"]; !ok {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "iat claim not found in attestation"}
	}

	// attested_keys: REQUIRED, non-empty array of JWKs
	attestedKeys, ok := claims["attested_keys"]
	if !ok {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "attested_keys claim not found in attestation"}
	}
	keysArr, ok := attestedKeys.([]any)
	if !ok || len(keysArr) == 0 {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "attested_keys must be a non-empty array"}
	}

	// nonce: OPTIONAL but REQUIRED when Credential Issuer has Nonce Endpoint
	if opts != nil && opts.CNonce != "" {
		nonce, ok := claims["nonce"]
		if !ok {
			return &Error{Err: ErrInvalidNonce, ErrorDescription: "nonce claim not found in attestation but c_nonce was provided"}
		}
		if nonce != opts.CNonce {
			return &Error{Err: ErrInvalidNonce, ErrorDescription: "nonce claim does not match server-provided c_nonce"}
		}
	}

	// TODO: Implement signature verification against trusted attestation issuers
	// This requires establishing trust in the attestation issuer

	return nil
}

// VerifyProof verifies the key proof according to OpenID4VCI 1.0 Appendix F.4
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-verifying-proof
//
// To validate a key proof, the Credential Issuer MUST ensure that:
// - all required claims for that proof type are contained
// - the key proof is explicitly typed using header parameters
// - the header parameter indicates a registered asymmetric digital signature algorithm, not "none"
// - the signature on the key proof verifies with the public key
// - the header parameter does not contain a private key
// - if the server has a Nonce Endpoint, the nonce matches the server-provided c_nonce
// - the creation time is within an acceptable window
func (c *CredentialRequest) VerifyProof(publicKey crypto.PublicKey) error {
	return c.VerifyProofWithOptions(publicKey, nil)
}

// VerifyProofWithOptions verifies the key proof with additional options
func (c *CredentialRequest) VerifyProofWithOptions(publicKey crypto.PublicKey, opts *VerifyProofOptions) error {
	if c.Proof == nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "proof is required"}
	}

	if c.Proof.ProofType == "" {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "proof_type is required"}
	}

	switch c.Proof.ProofType {
	case "jwt":
		if c.Proof.JWT == "" {
			return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "jwt field is required for proof_type 'jwt'"}
		}
		return verifyJWTProof(c.Proof.JWT, publicKey, opts)

	case "di_vp":
		if c.Proof.DIVP == nil {
			return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "di_vp field is required for proof_type 'di_vp'"}
		}
		return verifyDIVPProof(c.Proof.DIVP, opts)

	case "attestation":
		if c.Proof.Attestation == "" {
			return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "attestation field is required for proof_type 'attestation'"}
		}
		return verifyAttestationProof(c.Proof.Attestation, opts)

	default:
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("unsupported proof_type: %s", c.Proof.ProofType)}
	}
}
