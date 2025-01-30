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

//TODO(mk): remove all fmt.println etc with better debug log or remove them before merge to main

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
	SignatureBytes    []byte

	VerifiableCredentials []*VC

	//TODO ta fram och lägg in presentation submission som en struct

	//DisclosedClaims []string // Claims disclosed by the Holder

	//TODO(mk): gör en struct istället för bool med fält för utfall, error, mm.
	ValidationResults map[string]bool // Validation results for different steps
}

// VC represents the structure for validating a Verifiable Credential inside a Verifiable Presentation.
type VC struct {
	// from presentation_submission in vp_token.payload for this vc (for example: jwt_vc or ldp_vc or other)
	Format string

	// jwt_vc fields
	RawToken                    string
	JWTTyp                      string //for example: "vc+sd-jwt" (set by the credential issuer)
	HeaderDecoded               string
	HeaderDecodedMap            map[string]interface{}
	PayloadDecoded              string
	PayloadDecodedMap           map[string]interface{}
	SignatureBytes              []byte
	SelectiveDisclosuresDecoded []string
	HolderBindingJWT            string

	//TODO ldp_vc
}

// Validate runs the full validation process including extract and decode of all data in the vp_token.
func (vp *VPToken) Validate(holderPublicKey interface{}) error {
	// top level jwt only
	if err := vp.parseDecryptAndDecodeVPToken(); err != nil {
		return err
	}

	//TODO(mk): find and extract the holders public key instead of param

	// 2. Verify the signature of the outer JWT (VP) using the Holder's public key.
	if err := vp.validateHolderSignature(holderPublicKey); err != nil {
		return err
	}

	if err := vp.parseDecodeVerifiableCredentials(); err != nil {
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

// extractAndDecodeTopLevel (decrypt - not supported yet), extract and decode the vp_token into its components: header, payload, and signature.
func (vp *VPToken) parseDecryptAndDecodeVPToken() error {
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

	signatureBytes, err := base64.RawURLEncoding.DecodeString(parsedToken.signatureEncoded)
	if err != nil {
		return err
	}

	vp.HeaderDecoded = headerDecoded
	vp.HeaderDecodedMap = headerMap
	vp.PayloadDecoded = payloadDecoded
	vp.PayloadDecodedMap = payloadMap
	vp.SignatureBytes = signatureBytes
	//TODO: handle remainingParts (if exists), see parse func for more info

	return nil
}

func (vp *VPToken) parseDecodeVerifiableCredentials() error {
	vcResult := gjson.Get(vp.PayloadDecoded, "vp.verifiableCredential")
	if !vcResult.Exists() || !vcResult.IsArray() {
		return errors.New("verifiable credentials key not found in vp_token payload")
	}
	vcList := vcResult.Array()
	if len(vcList) == 0 {
		return errors.New("zero verifiable credentials in vp_token payload")
	}

	psResult := gjson.Get(vp.PayloadDecoded, "presentation_submission")
	if !psResult.Exists() {
		return errors.New("presentation_submission not found in vp_token payload")
	}
	descriptorMap := gjson.Get(vp.PayloadDecoded, "presentation_submission.descriptor_map")
	if !descriptorMap.Exists() || !descriptorMap.IsArray() {
		return errors.New("descriptor_map not found or invalid format")
	}
	var descriptors []struct {
		ID     string
		Format string
		Path   string
	}
	for _, descriptor := range descriptorMap.Array() {
		descID := descriptor.Get("id").String()
		format := descriptor.Get("format").String()
		path := descriptor.Get("path").String()
		if descID != "" && format != "" && path != "" {
			descriptors = append(descriptors, struct {
				ID     string
				Format string
				Path   string
			}{ID: descID, Format: format, Path: path})
		}
	}

	vp.VerifiableCredentials = make([]*VC, 0)

	for i, vcInPayload := range vcList {
		vcString := vcInPayload.String()

		//Try to match VC with descriptor_map using path
		var matchedDescriptor *struct {
			ID     string
			Format string
			Path   string
		}
		for _, d := range descriptors {
			if d.Path == fmt.Sprintf("$.vp.verifiableCredential[%d]", i) { // Dynamic matching
				matchedDescriptor = &d
				break
			}
		}

		// No match found, set  "unknown"
		format := "unknown"
		path := "unknown"
		if matchedDescriptor != nil {
			format = matchedDescriptor.Format
			path = matchedDescriptor.Path
		}

		fmt.Printf("\n✅ Credential [%d]:\n", i+1)
		fmt.Printf("  Descriptor ID: %s\n", matchedDescriptor.ID)
		fmt.Printf("  Format: %s\n", format)
		fmt.Printf("  Path: %s\n", path)
		fmt.Printf("  Data: %s\n", vcString)

		vc := &VC{
			RawToken: vcString,
		}

		switch format {
		case "jwt_vc":
			err := vc.parseAndDecodeJWTVC()
			if err != nil {
				return err
			}
		case "ldp_vc":
			// TODO: Implement JSON-LD VC parsing
			return fmt.Errorf("not supported VC-format: %s", format)
		default:
			return fmt.Errorf("unknown VC-format:" + format)
			//continue //TODO: ska vi se okänt format som ett fel eller ska vi jobba vidare med de vc's vi kan?
		}

		vp.VerifiableCredentials = append(vp.VerifiableCredentials, vc)
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
	parsedVPToken := &parsedVPToken{
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
		//TODO(mk): handle that the vp_token is a JWE (decrypt it)
		return nil, fmt.Errorf("JWE (encrypted) not supported yet!")
	}

	parsedVPToken.headerEncoded = tokenParts[0]
	parsedVPToken.payloadEncoded = tokenParts[1]
	parsedVPToken.signatureEncoded = tokenParts[2]

	if len(parts) > 1 {
		//TODO: handle remainingParts := parts[1:] ie what is after the jws parts in the vp_token
	}

	return parsedVPToken, nil
}

type parsedVC struct {
	raw string

	headerEncoded               string
	payloadEncoded              string
	signatureEncoded            string
	selectiveDisclosuresEncoded []string
	holderBindingJWT            string
}

// parseAndDecodeJWTVC func to parse and handle JWT VC with if exists: Selective Disclosures and/or Holder Binding
func (vc *VC) parseAndDecodeJWTVC() error {
	if vc.RawToken == "" {
		return fmt.Errorf("jwtVC parse and decode failed: empty VC")
	}

	parsedVC := &parsedVC{
		raw: vc.RawToken, // For debugging
	}

	parts := strings.Split(vc.RawToken, "~")
	tokenPart := parts[0]
	tokenParts := strings.Split(tokenPart, ".")

	if len(tokenParts) == 2 {
		return fmt.Errorf("the VC has to be a JWS (signed) or a JWE")
	}
	if len(tokenParts) != 3 && len(tokenParts) != 5 {
		return fmt.Errorf("the VC has an invalid JWS/JWE-structure")
	}
	if len(tokenParts) == 5 {
		return fmt.Errorf("the VC is a JWE (encrypted) – not supported yet")
	}

	parsedVC.headerEncoded = tokenParts[0]
	parsedVC.payloadEncoded = tokenParts[1]
	parsedVC.signatureEncoded = tokenParts[2]

	// Handle Selective Disclosures and Holder Binding
	if len(parts) > 1 {
		remainingParts := parts[1:] // all parts after jws
		for _, part := range remainingParts {
			if isJWT(part) {
				parsedVC.holderBindingJWT = part
				fmt.Println("holder binding on vc detected:", part)
			} else {
				parsedVC.selectiveDisclosuresEncoded = append(parsedVC.selectiveDisclosuresEncoded, part)
			}
		}
	}

	fmt.Println("parsedVC:", parsedVC)

	//TODO bryt ut - nedan är i princip samma kod som för vp_token nivån (standard jws delen)
	headerDecoded, err := decodeBase64URL(parsedVC.headerEncoded)
	if err != nil {
		return err
	}
	if !gjson.Valid(headerDecoded) {
		return fmt.Errorf("Header is not valid json in the vc")
	}

	payloadDecoded, err := decodeBase64URL(parsedVC.payloadEncoded)
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

	signatureBytes, err := base64.RawURLEncoding.DecodeString(parsedVC.signatureEncoded)
	if err != nil {
		return err
	}

	selectiveDisclosuresDecoded, err := decodeSelectiveDisclosures(parsedVC.selectiveDisclosuresEncoded)
	if err != nil {
		return err
	}

	//TODO ta fram och sätt vc.Format (från descriptor i vc_token.payload som pekar ut denna vc, dvs skicka in som paramter till dennna func
	//TODO ta fram och sätt vc.JWTTyp (från vc.header.typ om existerar)

	vc.HeaderDecoded = headerDecoded
	vc.HeaderDecodedMap = headerMap
	vc.PayloadDecoded = payloadDecoded
	vc.PayloadDecodedMap = payloadMap
	vc.SignatureBytes = signatureBytes
	vc.SelectiveDisclosuresDecoded = selectiveDisclosuresDecoded
	//TODO: packa upp HolderBindingJWT
	vc.HolderBindingJWT = parsedVC.holderBindingJWT

	return nil
}

func isJWT(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3 || len(parts) == 5
}

func decodeSelectiveDisclosures(encodedDisclosures []string) ([]string, error) {
	var decodedDisclosures []string

	for _, encoded := range encodedDisclosures {
		decodedBytes, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("failed to base64url decode selective disclosure: %v", err)
		}
		decodedDisclosures = append(decodedDisclosures, string(decodedBytes))
	}

	return decodedDisclosures, nil
}
