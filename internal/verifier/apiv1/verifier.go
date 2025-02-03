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

type ProcessType int

const (
	FULL_VALIDATION ProcessType = iota
	ONLY_EXTRACT_JSON
)

func (p ProcessType) String() string {
	switch p {
	case FULL_VALIDATION:
		return "FULL_VALIDATION"
	case ONLY_EXTRACT_JSON:
		return "ONLY_EXTRACT_JSON"
	default:
		return "UNKNOWN"
	}
}

func isValidProcessType(p ProcessType) bool {
	return p == FULL_VALIDATION || p == ONLY_EXTRACT_JSON
}

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

	HeaderDecoded        string
	HeaderDecodedMap     map[string]interface{}
	PayloadDecoded       string
	PayloadDecodedMap    map[string]interface{}
	HolderSignatureBytes []byte

	VerifiableCredentials []*VC

	//TODO ta fram och lägg in presentation submission som en struct (extraheras inom extractVerifiableCredentials)

	//DisclosedClaims []string // Claims disclosed by the Holder

	//TODO(mk): gör en struct istället för bool med fält för utfall, error, mm.
	ValidationResults map[string]bool // Validation results for different steps
}

// VC represents the structure for validating a Verifiable Credential inside a Verifiable Presentation (vp_token).
type VC struct {
	RawToken string

	// from presentation_submission in vp_token.payload for this vc (for example: jwt_vc or ldp_vc or other)
	Format string

	// jwt_vc fields
	JWTTyp                      string //for example: "vc+sd-jwt" (set by the credential issuer)
	HeaderDecoded               string
	HeaderDecodedMap            map[string]interface{}
	HeaderVCTMDecoded           string
	HeaderVCTMDecodedMap        map[string]interface{}
	PayloadDecoded              string
	PayloadDecodedMap           map[string]interface{}
	IssuerSignatureBytes        []byte
	SelectiveDisclosuresDecoded []string
	HolderBindingJWT            string

	//TODO ldp_vc
}

// Validate process the vp_token depending on selected ProcessType.
func (vp *VPToken) Process(processType ProcessType, holderPublicKey interface{}) error {
	if !isValidProcessType(processType) {
		return errors.New("invalid process type")
	}

	// top level jwt only
	if err := vp.extractVPToken(); err != nil {
		return err
	}

	if processType == FULL_VALIDATION {
		//TODO(mk): find and extract the holders public key instead of param

		// 2. Verify the signature of the outer JWT (VP) using the Holder's public key.
		if err := vp.validateHolderSignature(holderPublicKey); err != nil {
			return err
		}

	}

	if err := vp.extractVerifiableCredentials(); err != nil {
		return err
	}

	if processType == ONLY_EXTRACT_JSON {
		// Break here to display decoded vp_token
		return nil
	}

	//TODO(mk): find and extract the holders public key instead of param

	// 3. Validate Issuer's Signatures on Embedded VC's
	// Extract and verify the signatures of all Verifiable Credentials using the Issuer's public key.
	if err := vp.validateIssuerSignatures(); err != nil {
		return err
	}

	// 4. Check Credential Validity for each VC
	// Ensure that credentials are not expired, revoked, or issued by untrusted issuers.
	if err := vp.validateVerifiableCredentials(); err != nil {
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
func (vp *VPToken) extractVPToken() error {
	parsedVP, err := parseVPToken(vp.RawToken)
	if err != nil {
		return err
	}

	vp.HeaderDecoded, vp.HeaderDecodedMap, err = decodeAndValidateJSON(parsedVP.headerEncoded, "Header")
	if err != nil {
		return err
	}

	vp.PayloadDecoded, vp.PayloadDecodedMap, err = decodeAndValidateJSON(parsedVP.payloadEncoded, "Payload")
	if err != nil {
		return err
	}

	vp.HolderSignatureBytes, err = base64.RawURLEncoding.DecodeString(parsedVP.signatureEncoded)
	if err != nil {
		return err
	}

	//TODO: handle remainingParts (if exists), see parseVPToken func for more info

	return nil
}

func (vp *VPToken) extractVerifiableCredentials() error {
	vcResult := gjson.Get(vp.PayloadDecoded, "vp.verifiableCredential")
	if !vcResult.Exists() || !vcResult.IsArray() {
		return errors.New("verifiable credentials key not found in vp_token payload")
	}
	vcList := vcResult.Array()
	if len(vcList) == 0 {
		return errors.New("zero verifiable credentials in vp_token payload")
	}

	//TODO(mk): set as a presentation_submission field in VPToken ---------------
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
	//----------------------------------------------------------------------

	vp.VerifiableCredentials = make([]*VC, 0)

	for i, vcInPayload := range vcList {
		vcToken := vcInPayload.String()

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
		descriptorID := "unknown"
		if matchedDescriptor != nil {
			descriptorID = matchedDescriptor.ID
		}
		fmt.Printf("  Descriptor ID: %s\n", descriptorID)
		fmt.Printf("  Format: %s\n", format)
		fmt.Printf("  Path: %s\n", path)
		fmt.Printf("  Data: %s\n", vcToken)

		vc := &VC{
			RawToken: vcToken,
			Format:   format,
		}
		switch format {
		case "jwt_vc":
			err := vc.extractJWTVC()
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

	fmt.Println("vp_token extracted:", vp)

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

// validateVerifiableCredentials checks the validity of the credentials.
func (vp *VPToken) validateVerifiableCredentials() error {
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

// extractJWTVC func to parse and handle JWT VC with if exists: Selective Disclosures and/or Holder Binding
func (vc *VC) extractJWTVC() error {
	if vc.RawToken == "" {
		return fmt.Errorf("jwtVC parse and decode failed: empty VC")
	}

	parsedVC, err := parseJWTVC(vc.RawToken)
	if err != nil {
		return err
	}

	fmt.Println("parsedVC:", parsedVC)

	vc.HeaderDecoded, vc.HeaderDecodedMap, err = decodeAndValidateJSON(parsedVC.headerEncoded, "Header")
	if err != nil {
		return err
	}
	headerTypResult := gjson.Get(vc.HeaderDecoded, "typ")
	if headerTypResult.Exists() {
		// ex: "vc+sd-jwt"
		vc.JWTTyp = headerTypResult.String()
	}

	//TODO ta fram och sätt vc.JWTTyp (från vc.header.typ om existerar)

	vc.PayloadDecoded, vc.PayloadDecodedMap, err = decodeAndValidateJSON(parsedVC.payloadEncoded, "Payload")
	if err != nil {
		return err
	}

	vc.IssuerSignatureBytes, err = base64.RawURLEncoding.DecodeString(parsedVC.signatureEncoded)
	if err != nil {
		return err
	}

	vc.SelectiveDisclosuresDecoded, err = decodeSDs(parsedVC.selectiveDisclosuresEncoded)
	if err != nil {
		return err
	}

	//TODO: extract HolderBindingJWT string to its parts
	vc.HolderBindingJWT = parsedVC.holderBindingJWT

	headerVCTMResult := gjson.Get(vc.HeaderDecoded, "vctm")
	if headerVCTMResult.Exists() && headerVCTMResult.IsArray() {
		headerVCTMArray := headerVCTMResult.Array()
		if len(headerVCTMArray) > 1 {
			return errors.New("Only one vctm string i vc.header.vctm (array) is currently supported")
		}
		vctmEncoded := headerVCTMArray[0].String()
		vctmDecoded, vctmMap, err := decodeVCTM(vctmEncoded)
		if err != nil {
			return err
		}
		vc.HeaderVCTMDecoded = vctmDecoded
		vc.HeaderVCTMDecodedMap = vctmMap
	}

	return nil
}

func parseJWTVC(rawJWTVCToken string) (*parsedVC, error) {
	parts := strings.Split(rawJWTVCToken, "~")
	tokenPart := parts[0]
	tokenParts := strings.Split(tokenPart, ".")

	if len(tokenParts) == 2 {
		return nil, errors.New("the VC has to be a JWS (signed) or a JWE")
	}
	if len(tokenParts) != 3 && len(tokenParts) != 5 {
		return nil, errors.New("the VC has an invalid JWS/JWE-structure")
	}
	if len(tokenParts) == 5 {
		return nil, errors.New("the VC is a JWE (encrypted) – not supported yet")
	}

	parsed := &parsedVC{
		raw:              rawJWTVCToken,
		headerEncoded:    tokenParts[0],
		payloadEncoded:   tokenParts[1],
		signatureEncoded: tokenParts[2],
	}

	// Handle Selective Disclosures and Holder Binding
	if len(parts) > 1 {
		for _, part := range parts[1:] {
			if isJWT(part) {
				parsed.holderBindingJWT = part
			} else {
				parsed.selectiveDisclosuresEncoded = append(parsed.selectiveDisclosuresEncoded, part)
			}
		}
	}

	return parsed, nil
}

func decodeAndValidateJSON(encodedJSONString, field string) (string, map[string]interface{}, error) {
	decoded, err := decodeBase64URL(encodedJSONString)
	if err != nil {
		return "", nil, fmt.Errorf("%s decoding failed: %v", field, err)
	}

	if !gjson.Valid(decoded) {
		return "", nil, fmt.Errorf("%s is not valid JSON", field)
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal([]byte(decoded), &jsonMap); err != nil {
		return "", nil, fmt.Errorf("%s JSON unmarshal failed: %v", field, err)
	}

	return decoded, jsonMap, nil
}

func decodeVCTM(vctmEncoded string) (string, map[string]interface{}, error) {
	vctmEncoded = strings.TrimRight(vctmEncoded, "=")

	decodedBytes, err := base64.RawURLEncoding.DecodeString(vctmEncoded)
	if err != nil {
		return "", nil, fmt.Errorf("base64 decode failed: %v", err)
	}

	vctmDecoded := string(decodedBytes)
	if !gjson.Valid(vctmDecoded) {
		return "", nil, errors.New("vctm is not valid JSON")
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal(decodedBytes, &jsonMap); err != nil {
		return vctmDecoded, nil, fmt.Errorf("json unmarshal failed: %v", err)
	}

	return vctmDecoded, jsonMap, nil
}

func isJWT(token string) bool {
	parts := strings.Split(token, ".")
	// jws or jwe
	return len(parts) == 3 || len(parts) == 5
}

func decodeSDs(encodedSDs []string) ([]string, error) {
	var decodedSDs []string

	for _, encodedSD := range encodedSDs {
		decodedBytes, err := base64.RawURLEncoding.DecodeString(encodedSD)
		if err != nil {
			return nil, fmt.Errorf("failed to base64url decode selective disclosure: %v", err)
		}
		decodedSDs = append(decodedSDs, string(decodedBytes))
	}

	return decodedSDs, nil
}
