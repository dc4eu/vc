package openid4vp

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-sd-jwt/disclosure"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tidwall/gjson"
	"strings"
	"time"
	//"vc/internal/verifier/apiv1"

	jose "github.com/go-jose/go-jose/v4"
	//"github.com/go-jose/go-jose/v4/jwk"
)

//TODO(mk): remove all fmt.println etc and implement "vettig" loggning

type ProcessConfig struct {
	ProcessType       ProcessType
	ValidationOptions ValidationOptions
}

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

type ValidationOptions struct {
	SkipAllSignatureChecks bool `json:"skip_all_signature_checks,omitempty"`
}

type AuthorizationResponseWrapper struct {
	authorizationResponse *AuthorizationResponse
	vpList                []*VerifiablePresentationWrapper

	//TODO(mk): remove key fields below when implemented so they are fetch from their real location(s)
	holderPublicKey interface{}
	jwePrivateKey   interface{}
	issuerPublicKey interface{}
}

func NewAuthorizationResponseWrapper(authorizationResponse *AuthorizationResponse) (*AuthorizationResponseWrapper, error) {
	if authorizationResponse == nil {
		return nil, errors.New("no authorizationResponse provided")
	}

	arw := &AuthorizationResponseWrapper{
		authorizationResponse: authorizationResponse,
	}

	return arw, nil
}

// Process TODO: en till returntyp ska till här för utfall när mer blivit klart
func (arw *AuthorizationResponseWrapper) Process(processConfig *ProcessConfig) error {
	if processConfig == nil {
		return errors.New("no processConfig provided")
	}
	if !isValidProcessType(processConfig.ProcessType) {
		return errors.New("invalid process type")
	}

	if arw.authorizationResponse.Error != "" {
		return fmt.Errorf("error recieved from holder: %s", arw.authorizationResponse.Error)
	}

	//TODO: check id_token here or before (if exists)

	if arw.authorizationResponse.PresentationSubmission == nil {
		return errors.New("no presentation_submission found in response")
	}

	if err := arw.extractAllVPTokens(); err != nil {
		return err
	}

	if processConfig.ProcessType == FULL_VALIDATION &&
		!processConfig.ValidationOptions.SkipAllSignatureChecks {
		if err := arw.checkAllVPsIntegrity(); err != nil {
			return err
		}
	}

	if err := arw.extractAllEmbeddedVCs(); err != nil {
		return err
	}

	if processConfig.ProcessType == ONLY_EXTRACT_JSON {
		// break here since everything now is extracted
		return nil
	}

	if !processConfig.ValidationOptions.SkipAllSignatureChecks {
		if err := arw.checkAllVCsIntegrity(); err != nil {
			return err
		}
	}

	if err := arw.checkAllSelectiveDisclosures(); err != nil {
		return err
	}

	//TODO: fortsätt refact/impl av process här....

	return nil

}

func (arw *AuthorizationResponseWrapper) extractAllVPTokens() error {
	if arw.authorizationResponse.VPTokens == nil || len(arw.authorizationResponse.VPTokens) == 0 {
		return errors.New("no vp_token found in response")
	}

	arw.vpList = make([]*VerifiablePresentationWrapper, 0)
	for index, vpTokenRaw := range arw.authorizationResponse.VPTokens {
		if vpTokenRaw.isJWTBased() {
			vp, err := NewVerifiablePresentationWrapper(vpTokenRaw.JWT)
			if err != nil {
				return err
			}

			vp.IndexInVPTokenArray = index
			vp.holderPublicKey = arw.holderPublicKey
			vp.jwePrivateKey = arw.jwePrivateKey

			if err := vp.extractVPToken(); err != nil {
				return err
			}
			vp.PresentationSubmission = arw.authorizationResponse.PresentationSubmission

			arw.vpList = append(arw.vpList, vp)
		} else if vpTokenRaw.isJSONBased() {
			return errors.New("vp_token (one element in vp_token array) has json-stucture format and is not yet supported!")
		} else {
			return errors.New("unknown format of vp_token (one element in vp_token array)")
		}
	}

	return nil
}

func (arw *AuthorizationResponseWrapper) checkAllVPsIntegrity() error {
	for _, vp := range arw.vpList {
		err := vp.checkVPTokenIntegrity()
		if err != nil {
			return fmt.Errorf("failed vp token integrity check: %w", err)
		}
	}
	return nil
}

func (arw *AuthorizationResponseWrapper) extractAllEmbeddedVCs() error {
	for _, vp := range arw.vpList {
		err := vp.extractVerifiableCredentials()
		if err != nil {
			return err
		}
	}
	return nil
}

func (arw *AuthorizationResponseWrapper) checkAllVCsIntegrity() error {
	for _, vp := range arw.vpList {
		err := vp.checkVerifiableCredentialsIntegrity()
		if err != nil {
			return err
		}
	}
	return nil
}

func (arw *AuthorizationResponseWrapper) checkAllSelectiveDisclosures() error {
	for _, vp := range arw.vpList {
		err := vp.checkSelectiveDisclosures()
		if err != nil {
			return err
		}
	}
	return nil
}

func (arw *AuthorizationResponseWrapper) ExtractVerificationRecordBasis() (*VerificationRecord, error) {
	record := &VerificationRecord{
		Sequence:               0,
		SessionID:              "",
		CallbackID:             "",
		ValidationResult:       ValidationMeta{},
		PresentationSubmission: arw.authorizationResponse.PresentationSubmission,
		VPResults:              make([]*VPResult, len(arw.vpList)),
	}

	for i, vp := range arw.vpList {
		record.VPResults[i] = &VPResult{
			RawToken:  vp.RawToken,
			VCResults: make([]*VCResult, len(vp.vcList)),
		}

		for j, vc := range vp.vcList {
			record.VPResults[i].VCResults[j] = &VCResult{
				RawJWT:                    vc.RawToken,
				VCT:                       "",
				ValidSelectiveDisclosures: vc.ValidSelectiveDisclosures,
				Claims:                    vc.PayloadDecodedMap,
			}
		}
	}

	return record, nil
}

// NewVerifiablePresentationWrapper initializes a new VerifiablePresentationWrapper instance from a raw token.
func NewVerifiablePresentationWrapper(jwt_based_vp_token string) (*VerifiablePresentationWrapper, error) {
	if jwt_based_vp_token == "" {
		return nil, errors.New("empty vp_token provided")
	}

	vp := &VerifiablePresentationWrapper{
		RawToken: jwt_based_vp_token,
	}

	return vp, nil
}

// VerifiablePresentationWrapper represents the structure for validating a Verifiable Presentation
type VerifiablePresentationWrapper struct {
	//JWT-based vp
	RawToken                        string // The raw input token
	RawTokenHasBeenDecryptedFromJWE bool
	RawJWSPartOfToken               string //only header.payload.signature without any ~

	HeaderDecoded        string
	HeaderDecodedMap     map[string]interface{}
	PayloadDecoded       string
	PayloadDecodedMap    map[string]interface{}
	HolderSignatureBytes []byte

	//TODO: JSON-structure based vp_token

	//Common for both JWT and JSON based vp
	IndexInVPTokenArray    int
	PresentationSubmission *PresentationSubmission
	vcList                 []*VerifiableCredentialWrapper

	//TODO(mk): remove key fields below when implemented so they are fetch from their real location(s)
	holderPublicKey interface{}
	jwePrivateKey   interface{}
	issuerPublicKey interface{} //FOR NOW: All embedded vc's in a vp must currently be signed by the same issuer key

}

// VerifiableCredentialWrapper represents the structure for validating a Verifiable Credential (can be used both as is and within a verifiable presentation)
type VerifiableCredentialWrapper struct {
	//Format from presentation_submission for this vc (for example: jwt_vc, ldp_vc or other)
	Format string

	//jwt based vc
	RawToken                            string // as sent from client; can for example be; header.payload.signature(~sd1~sd2~holderbinding~) or header.encrypted_key.iv.ciphertext.tag
	RawJWSPartOfToken                   string //only header.payload.signature without any ~
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

	ValidSelectiveDisclosures []*Disclosure

	//TODO: ldp_vc based vc

}

// Process process the vp_token depending on selected ProcessType.
// DEPRECATED: replaced by AuthorizationResponseWrapper.Process
func (vp *VerifiablePresentationWrapper) Process(processType ProcessType) error {
	if !isValidProcessType(processType) {
		return errors.New("invalid process type")
	}

	// 1. parse, decrypt and decode top level jwt only (the vp_token level)
	if err := vp.extractVPToken(); err != nil {
		return err
	}

	if processType == FULL_VALIDATION {
		// 2. verify the signature of the outer JWT (VP) using the Holder's public key.
		// Ensure that it's not expired, revoked, or issued by untrusted holder (wallet), etc.
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

	// 4. Validate Issuer's Signatures on Embedded VerifiableCredentialWrapper's
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

	// 8. Persist verified credentials
	//TODO: analysera utfall och om allt är OK, persistera/lägg på en kö; alla vc's inkl. nödvändiga metadata för ev. konsumtion av en authentic_source men även stöd för att kunna ta emot revokeringsinfo(?) (import)
}

// extractAndDecodeTopLevel (decrypt - not supported yet), extract and decode the vp_token into its components: header, payload, and signature.
func (vp *VerifiablePresentationWrapper) extractVPToken() error {
	parsedVP, err := vp.parseVPToken()
	if err != nil {
		return err
	}

	vp.RawJWSPartOfToken = parsedVP.rawJWSPartOfToken

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

func (vp *VerifiablePresentationWrapper) extractVerifiableCredentials() error {
	if vp.PresentationSubmission == nil {
		return errors.New("no presentation submission found")
	}
	if len(vp.PresentationSubmission.DescriptorMap) != 1 {
		return errors.New("only one PresentationSubmission.DescriptorMap is currently supported")
	}

	vp.vcList = make([]*VerifiableCredentialWrapper, 0)
	for _, descriptor := range vp.PresentationSubmission.DescriptorMap {
		if descriptor.PathNested != nil {
			return fmt.Errorf("pathnested in presentation_submission not yet supported!")
		}
		fmt.Println(descriptor.ID)
		fmt.Println(descriptor.Path)
		fmt.Println(descriptor.Format)

		if descriptor.Path != "$" {
			return fmt.Errorf("only path='$' is currently supported for vc placement")
		}
		//Clients using "application/x-www-form-urlencoded" may decode '+' as space, so we must also accept the space variant.
		if descriptor.Format != "vc+sd-jwt" && descriptor.Format != "vc sd-jwt" {
			return fmt.Errorf("only format='vc+sd-jwt' (or 'vc sd-jwt') is currently supported as vc format")
		}

		vc := &VerifiableCredentialWrapper{
			RawToken: vp.RawToken, //In first supported scenario the vp and vc is the same (direct_post.jwt with vc+sd-jwt)
			Format:   descriptor.Format,
		}
		switch descriptor.Format {
		case "vc+sd-jwt", "vc sd-jwt":
			err := vc.extractJWTVC()
			if err != nil {
				return err
			}
		case "ldp_vc":
			// TODO: Implement JSON-LD VerifiableCredentialWrapper parsing
			return fmt.Errorf("not supported VerifiableCredentialWrapper-format: %s", descriptor.Format)
		default:
			return fmt.Errorf("unknown or not supported VerifiableCredentialWrapper-format: %s", descriptor.Format)
			//continue //TODO: ska vi se okänt format som ett fel eller ska vi jobba vidare med de vc's vi kan om allt finns med som presentation definition uppfylls?
		}
		vp.vcList = append(vp.vcList, vc)
	}

	return nil
}

// checkVPTokenIntegrity verifies the signature of the outer JWT (vp_token jws).
func (vp *VerifiablePresentationWrapper) checkVPTokenIntegrity() error {
	parsedToken, err := jwt.Parse(vp.RawJWSPartOfToken, func(token *jwt.Token) (interface{}, error) {
		alg := token.Method.Alg()
		fmt.Printf("\nFound vp_token signing alg: %s\n", alg)
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
	return nil
}

// verifySelectiveDisclosure validates revealed selective disclosure claims.
func (vp *VerifiablePresentationWrapper) checkSelectiveDisclosures() error {
	for _, vc := range vp.vcList {
		if len(vc.RevealedSelectiveDisclosuresDecoded) == 0 {
			continue
		}

		err := vc.checkRevealedSelectiveDisclosures()
		if err != nil {
			return err
		}
	}
	return nil
}

func (vc *VerifiableCredentialWrapper) checkRevealedSelectiveDisclosures() error {
	sdAlgResults := gjson.Get(vc.PayloadDecoded, "_sd_alg")
	if !sdAlgResults.Exists() {
		return fmt.Errorf("_sd_alg not found in VerifiableCredentialWrapper")
	}
	sdHashAlg := sdAlgResults.String()

	var sdList []string
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
func (vp *VerifiablePresentationWrapper) checkHolderBindingsInEmbeddedVCs() error {
	//TODO impl checkHolderBindingsInEmbeddedVCs
	return nil
}

// checkPresentationRequirements ensures the VP matches the verifier's requirements.
func (vp *VerifiablePresentationWrapper) checkPresentationRequirements() error {
	//TODO impl checkPresentationRequirements
	return nil
}

// decodeBase64URL decodes a Base64URL-encoded string.
func (vp *VerifiablePresentationWrapper) decodeBase64URL(input string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

type parsedVPToken struct {
	raw               string
	rawJWSPartOfToken string

	headerEncoded    string
	payloadEncoded   string
	signatureEncoded string
}

func (vp *VerifiablePresentationWrapper) parseVPToken() (*parsedVPToken, error) {
	parsedVPToken := &parsedVPToken{
		// just to simplify debug
		raw: vp.RawToken,
	}

	// Split token at the first `~` to separate first token from disclosures and other stuff (if exists)
	parts := strings.SplitN(vp.RawToken, "~", 2)
	tokenPart := parts[0]

	parsedVPToken.rawJWSPartOfToken = tokenPart

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
		//TODO(mk): find and extract jwePrivateKey from the real source == the verifiers private key (the wallet encrypted using the verifiers public key)
		jwtBytes, err := DecryptJWE(vp.RawToken, vp.jwePrivateKey)
		if err != nil {
			return nil, err
		}

		// Replace raw token with decrypted jwt (the readable vp_token)
		vp.RawToken = string(jwtBytes)
		vp.RawTokenHasBeenDecryptedFromJWE = true
		return vp.parseVPToken()
		//return nil, fmt.Errorf("JWE (encrypted) not supported yet!")
	}

	parsedVPToken.headerEncoded = tokenParts[0]
	parsedVPToken.payloadEncoded = tokenParts[1]
	parsedVPToken.signatureEncoded = tokenParts[2]

	if len(parts) > 1 {
		//TODO: handle remainingParts := parts[1:] ie what might be after the jws parts in the vp_token
	}

	return parsedVPToken, nil
}

func (vp *VerifiablePresentationWrapper) checkVerifiableCredentialsIntegrity() error {
	for _, vc := range vp.vcList {
		err := vc.checkIntegrity(vp.issuerPublicKey)
		if err != nil {
			return err
		}
	}
	return nil
}

func (vc *VerifiableCredentialWrapper) checkIntegrity(issuerPublicKey interface{}) error {
	parsedToken, _ := jwt.Parse(vc.RawJWSPartOfToken, func(token *jwt.Token) (interface{}, error) {
		alg := token.Method.Alg()
		fmt.Printf("\nFound vc_token signing alg: %s\n", alg)
		//TODO(mk): find and extract the issuer public key from the real source instead of param
		return issuerPublicKey, nil
	})

	//TODO: TA UT err i jwt.Parse samt KOMMENTERA FRAM NEDAN NÄR ÄKTA issuerPublicKey FINNS TILLGÄNGLIG
	//if err != nil {
	//	return fmt.Errorf("VerifiableCredentialWrapper JWS-verification failed: %w", err)
	//}
	//if !parsedToken.Valid {
	//	return fmt.Errorf("VerifiableCredentialWrapper JWS not valid")
	//}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("VerifiableCredentialWrapper could not read JWT claims")
	}

	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		if time.Now().After(expTime) {
			return fmt.Errorf("VerifiableCredentialWrapper JWT has expired")
		}
	}

	if nbf, ok := claims["nbf"].(float64); ok {
		nbfTime := time.Unix(int64(nbf), 0)
		if time.Now().Before(nbfTime) {
			return fmt.Errorf("VerifiableCredentialWrapper JWT not valid yet (will be valid in the feature)")
		}
	}

	if iat, ok := claims["iat"].(float64); ok {
		iatTime := time.Unix(int64(iat), 0)
		if time.Now().Before(iatTime) {
			return fmt.Errorf("VerifiableCredentialWrapper JWT has a iat-value in the future")
		}
	}

	if iss, ok := claims["iss"].(string); ok {
		//TODO: Hårdkodad expectedIssuer "https://issuer.sunet.se" - ta in via config
		expectedIssuer := "https://ehic-issuer.wwwallet.org" //"https://issuer.sunet.se"
		if iss != expectedIssuer {
			return fmt.Errorf("VerifiableCredentialWrapper JWT issuer mismatch: expected %s, got %s", expectedIssuer, iss)
		}
	}

	if vct, ok := claims["vct"].(string); ok {
		//TODO: Hårdkodad expectedVCT "EHICCredential"
		expectedVCT := "urn:credential:ehic" //"EHICCredential"
		if vct != expectedVCT {
			return fmt.Errorf("VerifiableCredentialWrapper JWT vct mismatch: expected %s, got %s", expectedVCT, vct)
		}
	}

	//TODO(mk): check more claims: revocation mm

	//TODO: REFACTORISERA: kanske kontrollera _sd här, då de finns i claims???
	return nil
}

func DecryptJWE(jweStr string, key interface{}) ([]byte, error) {
	parts := strings.Split(jweStr, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("Invalid JWE format")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("Failed to decode JWE header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("Failed to parse JWE header: %w", err)
	}

	fmt.Println("JWE Header:", header)

	keyAlg := jose.KeyAlgorithm(header.Alg)
	contentEnc := jose.ContentEncryption(header.Enc)

	jwe, err := jose.ParseEncrypted(jweStr, []jose.KeyAlgorithm{keyAlg}, []jose.ContentEncryption{contentEnc})
	if err != nil {
		return nil, fmt.Errorf("Failed to parse JWE: %w", err)
	}

	jwtBytes, err := jwe.Decrypt(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt JWE: %w", err)
	}

	return jwtBytes, nil
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

// extractJWTVC func to parse and handle JWT VerifiableCredentialWrapper with if exists: Selective Disclosures and/or Holder Binding
func (vc *VerifiableCredentialWrapper) extractJWTVC() error {
	if vc.RawToken == "" {
		return fmt.Errorf("jwtVC parse and decode failed: empty VerifiableCredentialWrapper")
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

	//TODO: extract HolderBindingJWT string to its parts?
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

func (vc *VerifiableCredentialWrapper) parseJWTVC(rawJWTVCToken string) (*parsedVC, error) {
	parts := strings.Split(rawJWTVCToken, "~")
	tokenPart := parts[0]
	tokenParts := strings.Split(tokenPart, ".")

	if len(tokenParts) == 2 {
		return nil, errors.New("the VerifiableCredentialWrapper has to be a JWS (signed) or a JWE")
	}
	if len(tokenParts) != 3 && len(tokenParts) != 5 {
		return nil, errors.New("the VerifiableCredentialWrapper has an invalid JWS/JWE-structure")
	}
	if len(tokenParts) == 5 {
		return nil, errors.New("the VerifiableCredentialWrapper is a JWE (encrypted) – not supported yet")
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
	Salt  string      `json:"salt" bson:"salt"`
	Key   string      `json:"key" bson:"key"`
	Value interface{} `json:"value" bson:"value"`
}

// unmarshalDisclosure unmarshals a JSON-encoded disclosure string
func (vc *VerifiableCredentialWrapper) unmarshalDisclosure(encoded string) (*Disclosure, error) {
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
func (vc *VerifiableCredentialWrapper) validateSelectiveDisclosures(sdList []string, hashAlg string) error {
	hashFunc, err := vc.getHashFunc(hashAlg)
	if err != nil {
		return err
	}

	for _, encodedDisclosure := range vc.RevealedSelectiveDisclosuresDecoded {
		d, err := vc.unmarshalDisclosure(encodedDisclosure)
		if err != nil {
			return fmt.Errorf("failed to decode disclosure: %w", err)
		}

		computedHash, err := vc.computeDisclosureHash(d, hashFunc)
		if err != nil {
			return fmt.Errorf("failed to compute hash for disclosure: %w", err)
		}

		found := false
		for _, sd := range sdList {
			if sd == computedHash {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("invalid disclosure: %s", d.Key)
		} else {
			fmt.Println("disclosure found and valid:", d)
			vc.ValidSelectiveDisclosures = append(vc.ValidSelectiveDisclosures, d)
		}
	}

	return nil
}

// getHashFunc returns a crypto.Hash function based on algorithm name
func (vc *VerifiableCredentialWrapper) getHashFunc(hashAlg string) (crypto.Hash, error) {
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

func (vc *VerifiableCredentialWrapper) computeDisclosureHash(d *Disclosure, hashFunc crypto.Hash) (string, error) {
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
