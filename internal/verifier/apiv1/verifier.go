package apiv1

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tidwall/gjson"

	"strings"
	"time"
)

// NewVPToken initializes a new VPToken instance from a raw token.
func NewVPToken(vp_token string) (*VPToken, error) {
	if vp_token == "" {
		return nil, errors.New("empty vp_token provided")
	}

	vp := &VPToken{
		RawToken:          vp_token,
		ValidationResults: make(map[string]bool),
	}

	return vp, nil
}

// VPToken represents the structure for validating a Verifiable Presentation token.
type VPToken struct {
	RawToken string // The raw input token

	HeaderDecoded     string
	HeaderDecodedMap  map[string]interface{}
	PayloadDecoded    string
	PayloadDecodedMap map[string]interface{}
	SignatureDecoded  string

	VerifiableCredentialList *[]VC

	//TODO ta fram och lägg in presentation submission som en struct

	//DisclosedClaims []string // Claims disclosed by the Holder

	//TODO(mk): gör en struct istället för bool med fält för utfall, error, mm.
	ValidationResults map[string]bool // Validation results for different steps
}

// VC represents the structure for validating a Verifiable Credential.
type VC struct {
	//if jwt_vc or ldp_vc
	Format string
	Typ    string

	// jwt_vc
	RawToken          string
	HeaderDecodedMap  map[string]interface{}
	PayloadDecodedMap map[string]interface{}
	SignatureDecoded  string
	Disclosures       []string
	//TODO add HolderBinding

	//TODO ldp_vc
}

// Validate runs the full validation process including extract and decode of all data in the vp_token.
func (vp *VPToken) Validate(holderPublicKey interface{}) error {
	// 1. Extracts And decodes the VP token into its components (top level jwt only)
	if err := vp.extractAndDecodeVPToken(); err != nil {
		return err
	}

	//TODO(mk): find and extract the holders public key instead of param

	// 2. Verify the signature of the outer JWT (VP) using the Holder's public key.
	if err := vp.validateHolderSignature(holderPublicKey); err != nil {
		return err
	}

	if err := vp.extractAndDecodeVerifiableCredentials(); err != nil {
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

// TODO döp om till något i stil med parseDecryptAndDecodeVPToken
// extractAndDecodeTopLevel (decrypt - not supported yet), extract and decode the vp_token into its components: header, payload, and signature.
func (vp *VPToken) extractAndDecodeVPToken() error {
	parsedToken, err := parseVPToken(vp.RawToken)
	if err != nil {
		return err
	}

	headerDecoded, err := decodeBase64URL(parsedToken.headerEncoded)
	if err != nil {
		return err
	}
	if !gjson.Valid(headerDecoded) {
		return fmt.Errorf("Header is not valid json")
	}

	payloadDecoded, err := decodeBase64URL(parsedToken.payloadEncoded)
	if err != nil {
		return err
	}
	if !gjson.Valid(payloadDecoded) {
		return fmt.Errorf("Payload is not valid json")
	}

	headerMap := make(map[string]interface{})
	if err := json.Unmarshal([]byte(headerDecoded), &headerMap); err != nil {
		return err
	}

	payloadMap := make(map[string]interface{})
	if err := json.Unmarshal([]byte(payloadDecoded), &payloadMap); err != nil {
		return err
	}

	paddedSignature := parsedToken.signatureEncoded
	switch len(paddedSignature) % 4 {
	case 2:
		paddedSignature += "=="
	case 3:
		paddedSignature += "="
	}
	signatureBytes, err := base64.URLEncoding.DecodeString(paddedSignature)
	if err != nil {
		return err
	}
	// convert byte-array till en string (if signature actually is a text)
	signatureString := string(signatureBytes)

	vp.HeaderDecoded = headerDecoded
	vp.HeaderDecodedMap = headerMap
	vp.PayloadDecoded = payloadDecoded
	vp.PayloadDecodedMap = payloadMap
	vp.SignatureDecoded = signatureString

	//TODO: hantera vad som ev. finns i parsedVPToken.disclosures - kan vara så att vissa disclosures i själva verket är en egen jwt (den sista i så fall?)

	return nil
}

func (vp *VPToken) extractAndDecodeVerifiableCredentials() error {

	vcList := gjson.Get(vp.PayloadDecoded, "vp.verifiableCredential")
	if !vcList.Exists() || !vcList.IsArray() {
		return errors.New("verifiable credentials not found in vp_token payload")
	}

	//TODO ta ut presentation_submission för användning nedan samt för att avgöra om koden kan hantera denna typ av vc (och är samma som begärd från holdern i tidigare request)

	for _, vc := range vcList.Array() {
		fmt.Println(vc)

		//TODO avgör för varje vc via payload.presentation_submission.descriptor_map.format om det är jwt_vc (jwt)eller ldp_vc (json-ld)

		//TODO: parsa och extrahera varje vc -> VC

		//TODO: tilldela alla till vp.VerifiableCredentials
	}

	return nil
}

// validateHolderSignature verifies the signature of the outer JWT.
func (vp *VPToken) validateHolderSignature(holderPublicKey interface{}) error {
	// Placeholder for holder signature validation logic.
	// Typically involves extracting JWK from payload and verifying signature.

	parsedToken, err := jwt.Parse(vp.RawToken, func(token *jwt.Token) (interface{}, error) {
		alg := token.Method.Alg()
		fmt.Printf("\n🔍 Found vp_token signing alg: %s\n", alg)
		return holderPublicKey, nil
	})
	if err != nil {
		return fmt.Errorf("JWT-verification failed: %w", err)
	}

	if !parsedToken.Valid {
		return fmt.Errorf("JWT not valid")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("could not read JWR claims")
	}

	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		if time.Now().After(expTime) {
			return fmt.Errorf("JWT has expired")
		}
	}

	if nbf, ok := claims["nbf"].(float64); ok {
		nbfTime := time.Unix(int64(nbf), 0)
		if time.Now().Before(nbfTime) {
			return fmt.Errorf("JWT not valid yet (will be valid in the feature)")
		}
	}

	if iat, ok := claims["iat"].(float64); ok {
		iatTime := time.Unix(int64(iat), 0)
		if time.Now().Before(iatTime) {
			return fmt.Errorf("JWT has a iat-value in the future")
		}
	}

	//TODO(mk): check revocation
	//if jti, ok := claims["jti"].(string); ok {
	//	if revokedTokens[jti] {
	//		return fmt.Errorf("JWT is revoked")
	//	}
	//}

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

type parsedVPToken struct {
	raw string

	headerEncoded    string
	payloadEncoded   string
	signatureEncoded string
}

func parseVPToken(vpToken string) (*parsedVPToken, error) {
	result := &parsedVPToken{
		// just to simplify debug
		raw: vpToken,
	}

	// Split token at the first `~` to separate first token from disclosures and other stuff (if exists)
	parts := strings.SplitN(vpToken, "~", 2)
	tokenPart := parts[0]

	tokenParts := strings.Split(tokenPart, ".")

	if len(tokenParts) == 2 {
		return nil, fmt.Errorf("the token has to be a JWS (signed) or a JWE")
	}
	if len(tokenParts) != 3 && len(tokenParts) != 5 {
		return nil, fmt.Errorf("invalid JWS/JWE-structure")
	}
	if len(parts) == 5 {
		//TODO(mk): handle that the vp_token is a JWE (decrypt)
		return nil, fmt.Errorf("JWE (encrypted) not supported yet!")
	}

	result.headerEncoded = tokenParts[0]
	result.payloadEncoded = tokenParts[1]
	result.signatureEncoded = tokenParts[2]

	//TODO(mk): handle disclosures, holder bindings and other stuff??? if exist
	//if len(parts) > 1 {
	//	disclosureParts := strings.Split(parts[1], "~")
	//	//TODO(mk): check if any disclosePart is another jwt etc
	//	result.disclosures = disclosureParts
	//}

	return result, nil
}

type parsedVC struct {
	raw string

	header        string
	payload       string
	signature     string
	disclosures   []string
	holderBinding string
}
