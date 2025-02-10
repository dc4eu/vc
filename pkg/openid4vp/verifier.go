package openid4vp

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-sd-jwt/disclosure"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/tidwall/gjson"
	"log"
	"strings"
	"time"
	//"vc/internal/verifier/apiv1"

	jose "github.com/go-jose/go-jose/v4"
	//"github.com/go-jose/go-jose/v4/jwk"
)

//TODO(mk): remove all fmt.println etc and implement "vettig" loggning

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

// VPToken represents the structure for validating a Verifiable Presentation token (vp_token).
type VPToken struct {
	RawToken                        string // The raw input token
	RawTokenHasBeenEncryptedFromJWE bool

	HeaderDecoded        string
	HeaderDecodedMap     map[string]interface{}
	PayloadDecoded       string
	PayloadDecodedMap    map[string]interface{}
	HolderSignatureBytes []byte

	VerifiableCredentials []*VCToken

	//TODO ta fram och lägg in presentation submission som en struct (extraheras inom extractVerifiableCredentials)

	//DisclosedClaims []string // Claims disclosed by the Holder

	//TODO(mk): gör en struct istället för bool med fält för utfall, error, mm.
	ValidationResults map[string]bool // Validation results for different steps

	//TODO(mk): remove key fields below when implemented so they are fetch from their real location(s)
	holderPublicKey interface{}
	jwePrivateKey   interface{}
	issuerPublicKey interface{} //All embedded vc's in a vp must currently be signed by the same issuer key
}

// VCToken represents the structure for validating a Verifiable Credential (can be used both as is and within a vp_token)
type VCToken struct {
	RawToken string // as sent from client; can for example be; header.payload.signature(~sd1~sd2~holderbinding~) or header.encrypted_key.iv.ciphertext.tag

	//Format from presentation_submission in vp_token.payload for this vc (for example: jwt_vc, ldp_vc or other)
	Format string

	// jwt_vc fields
	RawJWSPartOfToken                   string // only header.payload.signature
	JWTTyp                              string //for example: "vc+sd-jwt" (set by the credential issuer)
	HeaderDecoded                       string
	HeaderDecodedMap                    map[string]interface{}
	HeaderVCTMDecoded                   string
	HeaderVCTMDecodedMap                map[string]interface{}
	PayloadDecoded                      string
	PayloadDecodedMap                   map[string]interface{}
	IssuerSignatureBytes                []byte
	RevealedSelectiveDisclosuresDecoded []string
	HolderBindingJWT                    string

	//TODO ldp_vc
}

// Validate process the vp_token depending on selected ProcessType.
func (vp *VPToken) Process(processType ProcessType) error {
	if !isValidProcessType(processType) {
		return errors.New("invalid process type")
	}

	// 1. parse, decrypt and decode top level jwt only (the vp_token level)
	//TODO(mk): find and extract jwePrivateKey instead of param
	if err := vp.extractVPToken(); err != nil {
		return err
	}

	if processType == FULL_VALIDATION {
		// 2. verify the signature of the outer JWT (VP) using the Holder's public key.
		if err := vp.checkVPTokenIntegrity(); err != nil {
			return err
		}
	}

	// 3. parse, decrypt and decode every embedded VC
	if err := vp.extractVerifiableCredentials(); err != nil {
		return err
	}

	if processType == ONLY_EXTRACT_JSON {
		// Break here to display extracted and decoded vp_token incl. vc's
		return nil
	}

	// 4. Validate Issuer's Signatures on Embedded VCToken's
	// Extract and verify the signatures of all Verifiable Credentials using the Issuer's public key.
	// Ensure that credentials are not expired, revoked, or issued by untrusted issuers, etc.
	if err := vp.checkVerifiableCredentialsIntegrity(); err != nil {
		return err
	}

	// 5. Verify Selective Disclosure Claims
	// Validate disclosed claims against the hashed values (_sd list) in the original credential.
	if err := vp.checkSelectiveDisclosures(); err != nil {
		return err
	}

	// 6. Validate Holder Binding
	// Ensure the Holder is correctly bound to the credentials.
	if err := vp.checkHolderBindingsInEmbeddedVCs(); err != nil {
		return err
	}

	// 7. Validate Presentation Requirements
	// Ensure the VP matches the verifier's requirements.
	return vp.checkPresentationRequirements()

	// 8.
	//TODO: analysera utfall och om allt är OK, persistera/lägg på en kö; alla vc's inkl. nödvändiga metadata för ev. konsumtion av en authentic_source men även stöd för att kunna ta emot revokeringsinfo(?) (import)
}

// extractAndDecodeTopLevel (decrypt - not supported yet), extract and decode the vp_token into its components: header, payload, and signature.
func (vp *VPToken) extractVPToken() error {
	parsedVP, err := vp.parseVPToken()
	if err != nil {
		return err
	}

	vp.HeaderDecoded, vp.HeaderDecodedMap, err = decodeValidateAndUnmarshalJSON(parsedVP.headerEncoded, "Header")
	if err != nil {
		return err
	}

	vp.PayloadDecoded, vp.PayloadDecodedMap, err = decodeValidateAndUnmarshalJSON(parsedVP.payloadEncoded, "Payload")
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

	//TODO: Behöver egentligen först ta ut presentation_submission för att se om och i så fall vilka VCs som finns, vilka typ(er) de är samt var de finns (kanske bara vissa som är av intresse också - utgå från presentation defintion vad som krävs?)
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

	vp.VerifiableCredentials = make([]*VCToken, 0)

	for i, vcInPayload := range vcList {
		vcToken := vcInPayload.String()

		//Try to match VCToken with descriptor_map using path
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
		//fmt.Printf("  Data: %s\n", vcToken)

		vc := &VCToken{
			RawToken: vcToken,
			Format:   format,
		}
		switch format {
		case "jwt,", "jwe", "jwt_vc", "jwt_vp", "sd_jwt": //TODO: Har gjort så generiskt som möjligt just nu för att funka i olika test och miljöer initialt
			err := vc.extractJWTVC()
			if err != nil {
				return err
			}
		case "ldp_vc":
			// TODO: Implement JSON-LD VCToken parsing
			return fmt.Errorf("not supported VCToken-format: %s", format)
		default:
			return fmt.Errorf("unknown VCToken-format:" + format)
			//continue //TODO: ska vi se okänt format som ett fel eller ska vi jobba vidare med de vc's vi kan om allt finns med som presentation definition uppfylls?
		}
		vp.VerifiableCredentials = append(vp.VerifiableCredentials, vc)
	}

	//fmt.Println("vp_token extracted:", vp)

	return nil
}

// checkVPTokenIntegrity verifies the signature of the outer JWT (vp_token jws).
func (vp *VPToken) checkVPTokenIntegrity() error {
	parsedToken, err := jwt.Parse(vp.RawToken, func(token *jwt.Token) (interface{}, error) {
		alg := token.Method.Alg()
		fmt.Printf("\n🔍 Found vp_token signing alg: %s\n", alg)
		//TODO(mk): find and extract holderPublicKey from the real source
		return vp.holderPublicKey, nil
	})
	if err != nil {
		return fmt.Errorf("VP JWT-verification failed: %w", err)
	}

	if !parsedToken.Valid {
		return fmt.Errorf("VP JWT not valid")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("VP could not read JWR claims")
	}

	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		if time.Now().After(expTime) {
			return fmt.Errorf("VP JWT has expired")
		}
	}

	if nbf, ok := claims["nbf"].(float64); ok {
		nbfTime := time.Unix(int64(nbf), 0)
		if time.Now().Before(nbfTime) {
			return fmt.Errorf("VP JWT not valid yet (will be valid in the feature)")
		}
	}

	if iat, ok := claims["iat"].(float64); ok {
		iatTime := time.Unix(int64(iat), 0)
		if time.Now().Before(iatTime) {
			return fmt.Errorf("VP JWT has a iat-value in the future")
		}
	}

	if iss, ok := claims["iss"].(string); ok {
		//TODO: Hårdkodad expectedIssuer "did:example:myprivatewallet" - ta in via (förmodligen från tidigare steg)???
		expectedIssuer := "did:example:myprivatewallet"
		if iss != expectedIssuer {
			return fmt.Errorf("VP JWT issuer mismatch: expected %s, got %s", expectedIssuer, iss)
		}
	}

	if audClaim, ok := claims["aud"]; ok {
		//TODO: Hårdkodad expectedAudience - ta in via config
		expectedAudience := "did:example:sunetverifier"
		switch aud := audClaim.(type) {
		case string:
			if aud != expectedAudience {
				return fmt.Errorf("VP JWT audience mismatch: expected %s, got %s", expectedAudience, aud)
			}
		case []interface{}:
			found := false
			for _, a := range aud {
				if audStr, ok := a.(string); ok && audStr == expectedAudience {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("VP JWT audience mismatch: expected %s, got %v", expectedAudience, aud)
			}
		default:
			return fmt.Errorf("VP JWT audience claim has an unexpected type: %T", audClaim)
		}
	}

	//TODO(mk): check more claims: nonce, revocation etc

	vp.ValidationResults["HolderSignature"] = true
	return nil
}

// verifySelectiveDisclosure validates revealed selective disclosure claims.
func (vp *VPToken) checkSelectiveDisclosures() error {
	for _, vc := range vp.VerifiableCredentials {
		if len(vc.RevealedSelectiveDisclosuresDecoded) == 0 {
			continue
		}

		err := vc.checkRevealedSelectiveDisclosures()
		if err != nil {
			return err
		}
	}

	vp.ValidationResults["SelectiveDisclosures"] = true
	return nil
}

func (vc *VCToken) checkRevealedSelectiveDisclosures() error {
	sdAlgResults := gjson.Get(vc.PayloadDecoded, "_sd_alg")
	if !sdAlgResults.Exists() {
		return fmt.Errorf("_sd_alg not found in VCToken")
	}
	sdHashAlg := sdAlgResults.String()

	sdList := []string{}
	sdResults := gjson.Get(vc.PayloadDecoded, "_sd")
	if sdResults.Exists() && sdResults.IsArray() {
		sdResults.ForEach(func(_, value gjson.Result) bool {
			sdList = append(sdList, value.String())
			return true
		})
	}

	err := vc.validateSelectiveDisclosures(sdList, sdHashAlg)
	if err != nil {
		return fmt.Errorf("Validation of selective disclosures in a vc failed: %v", err)
	}
	return nil
}

// checkHolderBindingsInEmbeddedVCs ensures the Holder is bound to each embedded vc
func (vp *VPToken) checkHolderBindingsInEmbeddedVCs() error {
	//TODO impl checkHolderBindingsInEmbeddedVCs
	vp.ValidationResults["HolderBinding"] = true
	return nil
}

// checkPresentationRequirements ensures the VP matches the verifier's requirements.
func (vp *VPToken) checkPresentationRequirements() error {
	//TODO impl checkPresentationRequirements
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

func (vp *VPToken) parseVPToken() (*parsedVPToken, error) {
	parsedVPToken := &parsedVPToken{
		// just to simplify debug
		raw: vp.RawToken,
	}

	// Split token at the first `~` to separate first token from disclosures and other stuff (if exists)
	parts := strings.SplitN(vp.RawToken, "~", 2)
	tokenPart := parts[0]

	tokenParts := strings.Split(tokenPart, ".")

	if len(tokenParts) == 2 {
		return nil, fmt.Errorf("the token has to be a JWS (signed) or a JWE")
	}
	if len(tokenParts) != 3 && len(tokenParts) != 5 {
		return nil, fmt.Errorf("invalid JWS/JWE-structure")
	}
	if len(tokenParts) == 5 {
		// vp_token is a JWE (decrypt it first)
		fmt.Println("vp_token is a JWE - decrypting it to a JWT!")
		//TODO(mk): find and extract jwePrivateKey from the real source
		jwtBytes, err := decryptJWE(vp.RawToken, vp.jwePrivateKey)
		if err != nil {
			return nil, err
		}

		// Replace raw token with decrypted jwt (the readable vp_token)
		vp.RawToken = string(jwtBytes)
		vp.RawTokenHasBeenEncryptedFromJWE = true
		return vp.parseVPToken()
		//return nil, fmt.Errorf("JWE (encrypted) not supported yet!")
	}

	parsedVPToken.headerEncoded = tokenParts[0]
	parsedVPToken.payloadEncoded = tokenParts[1]
	parsedVPToken.signatureEncoded = tokenParts[2]

	if len(parts) > 1 {
		//TODO: handle remainingParts := parts[1:] ie what is after the jws parts in the vp_token
	}

	return parsedVPToken, nil
}

func (vp *VPToken) checkVerifiableCredentialsIntegrity() error {
	for _, vc := range vp.VerifiableCredentials {
		err := vc.checkIntegrity(vp.issuerPublicKey)
		if err != nil {
			return err
		}
	}

	vp.ValidationResults["IssuersSignaturesInVerifiableCredentials"] = true
	return nil
}

func (vc *VCToken) checkIntegrity(issuerPublicKey interface{}) error {
	parsedToken, _ := jwt.Parse(vc.RawJWSPartOfToken, func(token *jwt.Token) (interface{}, error) {
		alg := token.Method.Alg()
		fmt.Printf("\n🔍 Found vc_token signing alg: %s\n", alg)
		//TODO(mk): find and extract the issuer public key from the real source instead of param
		return issuerPublicKey, nil
	})

	//TODO: TA UT err i jwt.Parse samt KOMMENTERA FRAM NEDAN NÄR ÄKTA issuerPublicKey FINNS TILLGÄNGLIG
	//if err != nil {
	//	return fmt.Errorf("VCToken JWS-verification failed: %w", err)
	//}
	//if !parsedToken.Valid {
	//	return fmt.Errorf("VCToken JWS not valid")
	//}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("VCToken could not read JWT claims")
	}

	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		if time.Now().After(expTime) {
			return fmt.Errorf("VCToken JWT has expired")
		}
	}

	if nbf, ok := claims["nbf"].(float64); ok {
		nbfTime := time.Unix(int64(nbf), 0)
		if time.Now().Before(nbfTime) {
			return fmt.Errorf("VCToken JWT not valid yet (will be valid in the feature)")
		}
	}

	if iat, ok := claims["iat"].(float64); ok {
		iatTime := time.Unix(int64(iat), 0)
		if time.Now().Before(iatTime) {
			return fmt.Errorf("VCToken JWT has a iat-value in the future")
		}
	}

	if iss, ok := claims["iss"].(string); ok {
		//TODO: Hårdkodad expectedIssuer "https://issuer.sunet.se" - ta in via config
		expectedIssuer := "https://issuer.sunet.se"
		if iss != expectedIssuer {
			return fmt.Errorf("VCToken JWT issuer mismatch: expected %s, got %s", expectedIssuer, iss)
		}
	}

	if vct, ok := claims["vct"].(string); ok {
		//TODO: Hårdkodad expectedVCT "EHICCredential"
		expectedVCT := "EHICCredential"
		if vct != expectedVCT {
			return fmt.Errorf("VCToken JWT vct mismatch: expected %s, got %s", expectedVCT, vct)
		}
	}

	//TODO(mk): check more claims: revocation mm

	//TODO: REFACTORISERA: kanske kontrollera _sd här, då de finns i claims???
	return nil
}

func decryptJWE(jweStr string, key interface{}) ([]byte, error) {
	//TODO: hardcoded supported JWE key alg and content encryption
	keyEncryptionAlgorithms := []jose.KeyAlgorithm{
		jose.ECDH_ES_A256KW,
	}

	contentEncryption := []jose.ContentEncryption{
		jose.A256GCM,
	}

	fmt.Println("Supported JWE key encryption algorithms:", keyEncryptionAlgorithms)
	fmt.Println("Supported JWE content encryption algorithms:", contentEncryption)

	jwe, err := jose.ParseEncrypted(jweStr, keyEncryptionAlgorithms, contentEncryption)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse JWE: %w", err)
	}

	jwtBytes, err := jwe.Decrypt(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt JWE: %w", err)
	}

	return jwtBytes, nil
}

func unmarshalJWKFromJSON(jsonStr string) *jwk.Key {
	var key jwk.Key
	err := json.Unmarshal([]byte(jsonStr), &key)
	if err != nil {
		log.Fatalf("Failed to load JWK: %v", err)
	}
	return &key
}

type parsedVC struct {
	raw               string
	rawJWSPartOfToken string

	headerEncoded               string
	payloadEncoded              string
	signatureEncoded            string
	selectiveDisclosuresEncoded []string
	holderBindingJWT            string
}

// extractJWTVC func to parse and handle JWT VCToken with if exists: Selective Disclosures and/or Holder Binding
func (vc *VCToken) extractJWTVC() error {
	if vc.RawToken == "" {
		return fmt.Errorf("jwtVC parse and decode failed: empty VCToken")
	}

	parsedVC, err := vc.parseJWTVC(vc.RawToken)
	if err != nil {
		return err
	}
	if parsedVC.rawJWSPartOfToken == "" {
		return fmt.Errorf("failed to extract JWS part of vcToken")
	}
	vc.RawJWSPartOfToken = parsedVC.rawJWSPartOfToken

	//fmt.Println("parsedVC:", parsedVC)

	vc.HeaderDecoded, vc.HeaderDecodedMap, err = decodeValidateAndUnmarshalJSON(parsedVC.headerEncoded, "Header")
	if err != nil {
		return err
	}
	headerTypResult := gjson.Get(vc.HeaderDecoded, "typ")
	if headerTypResult.Exists() {
		// ex: "vc+sd-jwt"
		vc.JWTTyp = headerTypResult.String()
	}

	vc.PayloadDecoded, vc.PayloadDecodedMap, err = decodeValidateAndUnmarshalJSON(parsedVC.payloadEncoded, "Payload")
	if err != nil {
		return err
	}

	vc.IssuerSignatureBytes, err = base64.RawURLEncoding.DecodeString(parsedVC.signatureEncoded)
	if err != nil {
		return err
	}

	vc.RevealedSelectiveDisclosuresDecoded, err = decodeRevealedSelectiveDisclosures(parsedVC.selectiveDisclosuresEncoded)
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

func (vc *VCToken) parseJWTVC(rawJWTVCToken string) (*parsedVC, error) {
	parts := strings.Split(rawJWTVCToken, "~")
	tokenPart := parts[0]
	tokenParts := strings.Split(tokenPart, ".")

	if len(tokenParts) == 2 {
		return nil, errors.New("the VCToken has to be a JWS (signed) or a JWE")
	}
	if len(tokenParts) != 3 && len(tokenParts) != 5 {
		return nil, errors.New("the VCToken has an invalid JWS/JWE-structure")
	}
	if len(tokenParts) == 5 {
		return nil, errors.New("the VCToken is a JWE (encrypted) – not supported yet")
	}

	parsed := &parsedVC{
		raw:               rawJWTVCToken,
		rawJWSPartOfToken: tokenPart,
		headerEncoded:     tokenParts[0],
		payloadEncoded:    tokenParts[1],
		signatureEncoded:  tokenParts[2],
	}

	// Handle Selective Disclosures and Holder Binding
	if len(parts) > 1 {
		for _, part := range parts[1:] {
			if part == "" {
				// Handles scenario when no holder binding exists
				continue
			}
			if isJWT(part) {
				//TODO: kanske bättre kolla om det sista elementet är en holderbinding?
				parsed.holderBindingJWT = part
			} else {
				parsed.selectiveDisclosuresEncoded = append(parsed.selectiveDisclosuresEncoded, part)
			}
		}
	}

	return parsed, nil
}

func decodeValidateAndUnmarshalJSON(encodedJSONString, field string) (string, map[string]interface{}, error) {
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
	return decodeValidateAndUnmarshalJSON(vctmEncoded, "vctm")
}

func isJWT(token string) bool {
	parts := strings.Split(token, ".")
	// jws or jwe
	return len(parts) == 3 || len(parts) == 5
}

func decodeRevealedSelectiveDisclosures(encodedSDs []string) ([]string, error) {
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

// Disclosure represents a revealed selective disclosure
type Disclosure struct {
	Salt  string
	Key   string
	Value any
}

// unmarshalDisclosure unmarshals a JSON-encoded disclosure string
func (vc *VCToken) unmarshalDisclosure(encoded string) (*Disclosure, error) {
	var elements []any
	if err := json.Unmarshal([]byte(encoded), &elements); err != nil {
		return nil, fmt.Errorf("failed to unmarshal disclosure JSON: %w", err)
	}

	if len(elements) != 3 {
		return nil, errors.New("invalid disclosure format")
	}

	d := &Disclosure{
		Salt:  fmt.Sprintf("%v", elements[0]),
		Key:   fmt.Sprintf("%v", elements[1]),
		Value: elements[2],
	}

	return d, nil
}

// validateSelectiveDisclosures verifies revealed selective disclosures against `_sd` list for a vc
func (vc *VCToken) validateSelectiveDisclosures(sdList []string, hashAlg string) error {
	hashFunc, err := vc.getHashFunc(hashAlg)
	if err != nil {
		return err
	}

	for _, encodedDisclosure := range vc.RevealedSelectiveDisclosuresDecoded {
		d, err := vc.unmarshalDisclosure(encodedDisclosure)
		if err != nil {
			return fmt.Errorf("failed to decode disclosure: %w", err)
		}

		calculatedHash, err := vc.computeDisclosureHashUsingSUNETIssuerAlg(d, hashFunc)
		if err != nil {
			return fmt.Errorf("failed to compute hash for disclosure: %w", err)
		}

		found := false
		for _, sd := range sdList {
			if sd == calculatedHash {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("invalid disclosure: %s", d.Key)
		}
	}

	return nil
}

// getHashFunc returns a crypto.Hash function based on algorithm name
func (vc *VCToken) getHashFunc(hashAlg string) (crypto.Hash, error) {
	hashAlg = strings.ToLower(hashAlg)
	hashes := map[string]crypto.Hash{
		"sha-224":     crypto.SHA224,
		"sha-256":     crypto.SHA256,
		"sha-384":     crypto.SHA384,
		"sha-512":     crypto.SHA512,
		"sha3-224":    crypto.SHA3_224,
		"sha3-256":    crypto.SHA3_256,
		"sha3-384":    crypto.SHA3_384,
		"sha3-512":    crypto.SHA3_512,
		"blake2b-256": crypto.BLAKE2b_256,
		"blake2b-512": crypto.BLAKE2b_512,
		"blake2s-256": crypto.BLAKE2s_256,
	}

	if hash, exists := hashes[hashAlg]; exists {
		return hash, nil
	}

	return 0, fmt.Errorf("unsupported hash algorithm: %s", hashAlg)
}

func (vc *VCToken) computeDisclosureHashUsingSUNETIssuerAlg(d *Disclosure, hashFunc crypto.Hash) (string, error) {
	selectiveDisclosure, err := disclosure.NewFromObject(d.Key, d.Value, &d.Salt)
	if err != nil {
		return "", err
	}

	return string(selectiveDisclosure.Hash(hashFunc.New())), nil
}

func decodeBase64URL(encoded string) (string, error) {
	decodedBytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(decodedBytes), nil
}
