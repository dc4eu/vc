package apiv1

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// VPToken represents the structure for validating a Verifiable Presentation token.
type VPToken struct {
	RawToken  string                 // The raw input token
	Header    map[string]interface{} // Decoded JWT header
	Payload   map[string]interface{} // Decoded JWT payload
	Signature string                 // Extracted JWT signature
	//TODO(mk): gör en struct för nedan
	DecodedCredentials []map[string]interface{} // Decoded Verifiable Credentials
	//TODO(mk): gör en struct för nedan
	DisclosedClaims []string // Claims disclosed by the Holder
	//TODO(mk): gör en struct för nedan
	ValidationResults map[string]bool // Validation results for different steps
}

// NewVPToken initializes a new VPToken instance from a raw token.
func NewVPToken(rawToken string) (*VPToken, error) {
	if rawToken == "" {
		return nil, errors.New("empty vp_token provided")
	}

	vp := &VPToken{
		RawToken:           rawToken,
		DecodedCredentials: make([]map[string]interface{}, 0),
		DisclosedClaims:    make([]string, 0),
		ValidationResults:  make(map[string]bool),
	}

	return vp, nil
}

// Validate runs the full validation process including extract and decode.
func (vp *VPToken) Validate() error {

	// 1. Extracts And decodes the VP token into its components
	if err := vp.extractAndDecode(); err != nil {
		return err
	}

	// 2. Verify Holder's Signature
	// Verify the signature of the outer JWT using the Holder's public key.
	if err := vp.validateHolderSignature(); err != nil {
		return err
	}

	// 3. Validate Issuer's Signatures on Embedded VC's
	// Extract and verify the signatures of all Verifiable Credentials using the Issuer's public key.
	if err := vp.validateIssuerSignatures(); err != nil {
		return err
	}

	// 4. Check Credential Validity for each VC
	// Ensure that credentials are not expired, revoked, or issued by untrusted issuers.
	if err := vp.validateCredentials(); err != nil {
		return err
	}

	// 5. Verify Selective Disclosure Claims
	// Validate disclosed claims against the hashed values in the original credential.
	if err := vp.verifySelectiveDisclosure(); err != nil {
		return err
	}

	// 6. Validate Holder Binding
	// Ensure the Holder is correctly bound to the credential.
	if err := vp.validateHolderBinding(); err != nil {
		return err
	}

	// 7. Validate Presentation Requirements
	// Ensure the VP matches the verifier's requirements.
	return vp.validatePresentationRequirements()
}

// extractAndDecode extracts and decodes the VP token into its components: header, payload, and signature.
// Validates its basic structure to ensure it conforms to the JWT standard.
func (vp *VPToken) extractAndDecode() error {
	tokenParts := strings.Split(vp.RawToken, ".")
	if len(tokenParts) != 3 {
		return errors.New("invalid token structure")
	}

	header, payload, signature := tokenParts[0], tokenParts[1], tokenParts[2]

	headerDecoded, err := decodeBase64URL(header)
	if err != nil {
		return err
	}

	payloadDecoded, err := decodeBase64URL(payload)
	if err != nil {
		return err
	}

	headerMap := make(map[string]interface{})
	payloadMap := make(map[string]interface{})

	if err := json.Unmarshal([]byte(headerDecoded), &headerMap); err != nil {
		return err
	}

	if err := json.Unmarshal([]byte(payloadDecoded), &payloadMap); err != nil {
		return err
	}

	vp.Header = headerMap
	vp.Payload = payloadMap
	vp.Signature = signature
	return nil
}

// validateHolderSignature verifies the signature of the outer JWT.
func (vp *VPToken) validateHolderSignature() error {
	// Placeholder for holder signature validation logic.
	// Typically involves extracting JWK from payload and verifying signature.
	vp.ValidationResults["HolderSignature"] = true
	return nil
}

// validateIssuerSignatures validates signatures of all embedded Verifiable Credentials.
func (vp *VPToken) validateIssuerSignatures() error {
	// Placeholder for issuer signature validation logic.
	// Extract VCs and validate their signatures using Issuer public keys.
	vp.ValidationResults["IssuerSignatures"] = true
	return nil
}

// validateCredentials checks the validity of the credentials.
func (vp *VPToken) validateCredentials() error {
	// Placeholder for checking credential validity (e.g., expiration, revocation).
	vp.ValidationResults["Credentials"] = true
	return nil
}

// verifySelectiveDisclosure validates selective disclosure claims.
func (vp *VPToken) verifySelectiveDisclosure() error {
	// Placeholder for validating _sd claims in the payload.
	vp.ValidationResults["SelectiveDisclosure"] = true
	return nil
}

// validateHolderBinding ensures the Holder is bound to the credential.
func (vp *VPToken) validateHolderBinding() error {
	// Placeholder for validating Holder binding logic.
	vp.ValidationResults["HolderBinding"] = true
	return nil
}

// validatePresentationRequirements ensures the VP matches the verifier's requirements.
func (vp *VPToken) validatePresentationRequirements() error {
	// Placeholder for matching claims with verifier requirements.
	vp.ValidationResults["PresentationRequirements"] = true
	return nil
}

// decodeBase64URL decodes a Base64URL-encoded string.
func (vp *VPToken) decodeBase64URL(input string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}
