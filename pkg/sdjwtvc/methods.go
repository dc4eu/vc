package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"sort"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"
)

// CredentialOptions contains optional parameters for credential building
type CredentialOptions struct {
	// DecoyDigests: number of decoy digests to add per _sd array (§4.2.5)
	DecoyDigests int
	// ExpirationDays: number of days until credential expires (default: 365)
	ExpirationDays int
}

// BuildCredential creates a complete SD-JWT credential with additional options
func (c *Client) BuildCredential(
	issuer string,
	kid string,
	privateKey any,
	vct string,
	documentData []byte,
	holderJWK any,
	vctm *VCTM,
	opts *CredentialOptions,
) (string, error) {
	// Set defaults
	if opts == nil {
		opts = &CredentialOptions{
			DecoyDigests:   0,
			ExpirationDays: 365,
		}
	}
	if opts.ExpirationDays == 0 {
		opts.ExpirationDays = 365
	}
	// Parse document data as generic map
	body := map[string]any{}
	if err := json.Unmarshal(documentData, &body); err != nil {
		return "", fmt.Errorf("failed to unmarshal document data: %w", err)
	}

	// Add standard JWT claims
	body["nbf"] = int64(time.Now().Unix())
	body["exp"] = time.Now().Add(time.Duration(opts.ExpirationDays) * 24 * time.Hour).Unix()
	body["iss"] = issuer
	body["jti"] = uuid.NewString()
	body["vct"] = vct

	// Add confirmation claim with holder's public key
	body["cnf"] = map[string]any{
		"jwk": holderJWK,
	}

	// Determine signing algorithm from private key
	signingMethod, algName := getSigningMethodFromKey(privateKey)

	// Create JWT header
	// Per SD-JWT VC draft-13 section 3.2.1: typ MUST be "dc+sd-jwt"
	// (also accepts "vc+sd-jwt" during transition period)
	header := map[string]any{
		"typ": "dc+sd-jwt",
		"kid": kid,
		"alg": algName,
	}

	// Encode VCTM in header
	vctmEncoded, err := vctm.Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode VCTM: %w", err)
	}
	header["vctm"] = vctmEncoded

	// Create selective disclosures using the provided VCTM
	token, disclosures, err := c.MakeCredentialWithOptions(sha256.New(), body, vctm, opts.DecoyDigests)
	if err != nil {
		return "", fmt.Errorf("failed to create selective disclosures: %w", err)
	}

	// Sign the JWT
	signedToken, err := Sign(header, token, signingMethod, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	// Combine signed JWT with disclosures
	signedToken = Combine(signedToken, disclosures, "")

	return signedToken, nil
}

// getSigningMethodFromKey determines the JWT signing method and algorithm name from the private key
func getSigningMethodFromKey(privateKey any) (jwt.SigningMethod, string) {
	// Check if the key is RSA
	if rsaKey, ok := privateKey.(*rsa.PrivateKey); ok {
		// Determine RSA algorithm based on key size
		keySize := rsaKey.N.BitLen()
		switch {
		case keySize >= 4096:
			return jwt.SigningMethodRS512, "RS512"
		case keySize >= 3072:
			return jwt.SigningMethodRS384, "RS384"
		default:
			return jwt.SigningMethodRS256, "RS256"
		}
	}

	// Check if the key is ECDSA
	if ecKey, ok := privateKey.(*ecdsa.PrivateKey); ok {
		// Determine algorithm based on the curve of the ECDSA key
		switch ecKey.Curve.Params().Name {
		case "P-256":
			return jwt.SigningMethodES256, "ES256"
		case "P-384":
			return jwt.SigningMethodES384, "ES384"
		case "P-521":
			return jwt.SigningMethodES512, "ES512"
		default:
			// Default to ES256 for unknown curves
			return jwt.SigningMethodES256, "ES256"
		}
	}

	// Default to ES256 if key type is unknown
	return jwt.SigningMethodES256, "ES256"
}

// MakeCredential creates a SD-JWT credential from the provided data and VCTM.
// It implements recursive selective disclosure per oauth-selective-disclosure-jwt-22.
func (c *Client) MakeCredential(hashMethod hash.Hash, data map[string]any, vctm *VCTM) (map[string]any, []string, error) {
	return c.MakeCredentialWithOptions(hashMethod, data, vctm, 0)
}

// MakeCredentialWithOptions creates a SD-JWT credential with optional decoy digests
// Per section 4.2.5: decoy digests obscure the actual number of claims
func (c *Client) MakeCredentialWithOptions(hashMethod hash.Hash, data map[string]any, vctm *VCTM, decoyCount int) (map[string]any, []string, error) {
	disclosures := []string{}

	// Set hash algorithm claim (section 4.1.1)
	// Determine algorithm name from the hash interface
	algName, err := getHashAlgorithmName(hashMethod)
	if err != nil {
		return nil, nil, fmt.Errorf("unsupported hash algorithm: %w", err)
	}
	data["_sd_alg"] = algName

	// Sort claims by depth (deepest first) to ensure child claims are processed
	// before parent claims in recursive selective disclosure scenarios
	sortedClaims := sortClaimsByDepth(vctm.Claims)

	// Process claims recursively
	for _, claim := range sortedClaims {
		if claim.SD == "always" && len(claim.Path) > 0 {
			disclosure, hash, err := c.processClaimPath(data, claim.Path, hashMethod)
			if err != nil {
				return nil, nil, err
			}
			if disclosure != "" {
				disclosures = append(disclosures, disclosure)
				// Add hash to the appropriate _sd array
				if err := c.addHashToPath(data, claim.Path[:len(claim.Path)-1], hash); err != nil {
					return nil, nil, err
				}
			}
		}
	}

	// Add decoy digests if requested (section 4.2.5)
	if decoyCount > 0 {
		if err := c.addDecoyDigests(data, hashMethod, decoyCount); err != nil {
			return nil, nil, fmt.Errorf("failed to add decoy digests: %w", err)
		}
	}

	// Shuffle all _sd arrays to hide original claim order (section 4.2.4.1)
	// "The Issuer MUST hide the original order of the claims in the array"
	shuffleSDArrays(data)

	return data, disclosures, nil
}

// processClaimPath handles a single claim path, creating disclosure and removing from data
// Supports object properties per section 4.2.1. Array element support (section 4.2.2)
// requires additional path notation and is planned for future implementation.
func (c *Client) processClaimPath(data map[string]any, path []*string, hashMethod hash.Hash) (string, string, error) {
	if len(path) == 0 {
		return "", "", fmt.Errorf("empty path")
	}

	// Navigate to the parent container
	current := data
	for i := 0; i < len(path)-1; i++ {
		if path[i] == nil {
			return "", "", fmt.Errorf("nil path element at index %d", i)
		}

		next, ok := current[*path[i]]
		if !ok {
			// Path doesn't exist in data
			return "", "", nil
		}

		switch v := next.(type) {
		case map[string]any:
			current = v
		case []any:
			// Array element selective disclosure (section 4.2.2) requires index information
			// This would need extended path notation to specify array indices
			// For now, return error as this is not yet implemented
			return "", "", fmt.Errorf("array element selective disclosure requires index information in path")
		default:
			return "", "", fmt.Errorf("invalid path: non-object at %s", *path[i])
		}
	}

	// Get the final claim name for object property disclosure (section 4.2.1)
	claimName := path[len(path)-1]
	if claimName == nil {
		return "", "", fmt.Errorf("nil claim name")
	}

	// Per section 4.2.1.1: claim name MUST NOT be _sd, ..., or an existing permanently disclosed claim
	if *claimName == "_sd" || *claimName == "..." {
		return "", "", fmt.Errorf("claim name cannot be '_sd' or '...'")
	}

	// Get the value - this is an object property disclosure
	value, exists := current[*claimName]
	if !exists {
		// Claim doesn't exist in data
		return "", "", nil
	}

	// For nested objects that should be selectively disclosed recursively,
	// the value might already be processed (contain _sd arrays)
	// This handles recursive disclosures as per section 4.2.6

	// Create disclosure with cryptographically secure random salt
	// Per section 4.2.1: salt MUST be a string with recommended 128-bit entropy
	salt, err := generateSalt()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Create Disclosure for object property: [salt, claim_name, value]
	discloser := Discloser{
		Salt:      salt,
		ClaimName: *claimName,
		Value:     value,
	}

	// Hash the disclosure per section 4.2.3
	// "The input to the hash function MUST be the base64url-encoded Disclosure"
	sdHash, sdB64, _, err := discloser.Hash(hashMethod)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash disclosure: %w", err)
	}

	// Remove the claim from the object (digest goes in _sd array)
	// Per section 4.2.4.1
	delete(current, *claimName)

	return sdB64, sdHash, nil
}

// addHashToPath adds a hash to the _sd array at the specified path
// Per section 4.2.4.1: "Digests of Disclosures for object properties are added
// to an array under the new key _sd in the object"
func (c *Client) addHashToPath(data map[string]any, path []*string, hash string) error {
	current := data

	// Navigate to the target object
	for i, p := range path {
		if p == nil {
			return fmt.Errorf("nil path element at index %d", i)
		}

		next, ok := current[*p]
		if !ok {
			return fmt.Errorf("path not found: %s", *p)
		}

		nextMap, ok := next.(map[string]any)
		if !ok {
			return fmt.Errorf("non-object at path: %s", *p)
		}
		current = nextMap
	}

	// Ensure _sd key exists and is an array
	// Per section 4.2.4.1: "The _sd key MUST refer to an array of strings"
	if _, ok := current["_sd"]; !ok {
		current["_sd"] = []any{}
	}

	// Validate and append hash to _sd array
	sdArray, ok := current["_sd"].([]any)
	if !ok {
		return fmt.Errorf("_sd is not an array")
	}

	// Check for duplicate digests (section 7.1 step 4)
	// "If any digest value is encountered more than once in the Issuer-signed JWT
	// payload (directly or recursively via other Disclosures), the SD-JWT MUST be rejected"
	for _, existing := range sdArray {
		if existing == hash {
			return fmt.Errorf("duplicate digest detected: %s", hash)
		}
	}

	current["_sd"] = append(sdArray, hash)

	return nil
}

// addDecoyDigests adds decoy digests to _sd arrays to obscure the actual number of claims
// Per section 4.2.5: "An Issuer MAY add additional digests to the SD-JWT payload that are
// not associated with any claim. The purpose of such 'decoy' digests is to make it more
// difficult for an adversarial Verifier to see the original number of claims"
func (c *Client) addDecoyDigests(data map[string]any, hashMethod hash.Hash, decoyCount int) error {
	// Recursively add decoy digests to all _sd arrays
	return addDecoyDigestsRecursive(data, hashMethod, decoyCount)
}

// addDecoyDigestsRecursive recursively adds decoy digests to nested structures
func addDecoyDigestsRecursive(data map[string]any, hashMethod hash.Hash, decoyCount int) error {
	for key, value := range data {
		// Process nested objects
		if nested, ok := value.(map[string]any); ok {
			if err := addDecoyDigestsRecursive(nested, hashMethod, decoyCount); err != nil {
				return err
			}
		}

		// Add decoy digests to _sd arrays
		if key == "_sd" {
			if sdArray, ok := value.([]any); ok {
				// Generate decoy digests
				for i := 0; i < decoyCount; i++ {
					decoy, err := generateDecoyDigest(hashMethod)
					if err != nil {
						return fmt.Errorf("failed to generate decoy digest: %w", err)
					}
					sdArray = append(sdArray, decoy)
				}
				data[key] = sdArray
			}
		}
	}
	return nil
}

// generateDecoyDigest generates a decoy digest by hashing a random value
// Per section 4.2.5: "It is RECOMMENDED to create the decoy digests by hashing over
// a cryptographically secure random number"
func generateDecoyDigest(hashMethod hash.Hash) (string, error) {
	// Generate 32 bytes of random data
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Hash the random bytes
	hashMethod.Reset()
	_, err = hashMethod.Write(randomBytes)
	if err != nil {
		return "", err
	}

	// Base64url-encode the hash
	digest := base64.RawURLEncoding.EncodeToString(hashMethod.Sum(nil))
	return digest, nil
}

// shuffleSDArrays recursively shuffles all _sd arrays in the data structure
// Per section 4.2.4.1: "The Issuer MUST hide the original order of the claims in the array.
// To ensure this, it is RECOMMENDED to shuffle the array of hashes, e.g., by sorting it
// alphanumerically or randomly"
func shuffleSDArrays(data map[string]any) {
	for key, value := range data {
		switch v := value.(type) {
		case map[string]any:
			// Recursively process nested objects
			shuffleSDArrays(v)
		case []any:
			// Process array elements
			for _, elem := range v {
				if m, ok := elem.(map[string]any); ok {
					shuffleSDArrays(m)
				}
			}
		}

		// If this is an _sd array, shuffle it
		if key == "_sd" {
			if arr, ok := value.([]any); ok {
				// Sort alphanumerically as recommended in the spec
				sortSDArray(arr)
				data[key] = arr
			}
		}
	}
}

// sortSDArray sorts an _sd array alphanumerically
func sortSDArray(arr []any) {
	sort.Slice(arr, func(i, j int) bool {
		si, oki := arr[i].(string)
		sj, okj := arr[j].(string)
		if oki && okj {
			return si < sj
		}
		return false
	})
}

// generateSalt generates a cryptographically secure random salt
// Per spec section 4.2.1: "To achieve the recommended entropy of the salt,
// the Issuer can base64url-encode 128 bits of cryptographically secure random data"
func generateSalt() (string, error) {
	// 128 bits = 16 bytes
	saltBytes := make([]byte, 16)
	_, err := rand.Read(saltBytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(saltBytes), nil
}

// getHashAlgorithmName determines the hash algorithm name from a hash.Hash interface
// Returns the algorithm name as specified in IANA Named Information Hash Algorithm registry
// Per section 4.1.1, the _sd_alg value should use the hash algorithm name from this registry
func getHashAlgorithmName(h hash.Hash) (string, error) {
	// Determine algorithm by size, which is the most reliable method
	// since we can't directly inspect the concrete type without reflection
	size := h.Size()

	switch size {
	case 32: // 256 bits
		// Could be SHA-256 or SHA3-256
		// We'll default to SHA-256 as it's most common
		// To distinguish, we'd need to check the type, so we create reference hashes
		if isSHA256(h) {
			return "sha-256", nil
		}
		if isSHA3_256(h) {
			return "sha3-256", nil
		}
		return "sha-256", nil // default to SHA-256 for 32-byte hashes

	case 48: // 384 bits
		return "sha-384", nil

	case 64: // 512 bits
		// Could be SHA-512 or SHA3-512
		if isSHA512(h) {
			return "sha-512", nil
		}
		if isSHA3_512(h) {
			return "sha3-512", nil
		}
		return "sha-512", nil // default to SHA-512 for 64-byte hashes

	case 28: // 224 bits
		return "sha-224", nil

	default:
		return "", fmt.Errorf("unsupported hash size: %d bytes", size)
	}
}

// isSHA256 checks if the hash is SHA-256 by comparing behavior
func isSHA256(h hash.Hash) bool {
	h.Reset()
	testData := []byte("test")
	h.Write(testData)
	result := h.Sum(nil)
	h.Reset()

	// Compare with known SHA-256 hash
	ref := sha256.New()
	ref.Write(testData)
	expected := ref.Sum(nil)

	if len(result) != len(expected) {
		return false
	}
	for i := range result {
		if result[i] != expected[i] {
			return false
		}
	}
	return true
}

// isSHA3_256 checks if the hash is SHA3-256
func isSHA3_256(h hash.Hash) bool {
	h.Reset()
	testData := []byte("test")
	h.Write(testData)
	result := h.Sum(nil)
	h.Reset()

	// Compare with known SHA3-256 hash
	ref := sha3.New256()
	ref.Write(testData)
	expected := ref.Sum(nil)

	if len(result) != len(expected) {
		return false
	}
	for i := range result {
		if result[i] != expected[i] {
			return false
		}
	}
	return true
}

// isSHA512 checks if the hash is SHA-512
func isSHA512(h hash.Hash) bool {
	h.Reset()
	testData := []byte("test")
	h.Write(testData)
	result := h.Sum(nil)
	h.Reset()

	// Compare with known SHA-512 hash
	ref := sha512.New()
	ref.Write(testData)
	expected := ref.Sum(nil)

	if len(result) != len(expected) {
		return false
	}
	for i := range result {
		if result[i] != expected[i] {
			return false
		}
	}
	return true
}

// isSHA3_512 checks if the hash is SHA3-512
func isSHA3_512(h hash.Hash) bool {
	h.Reset()
	testData := []byte("test")
	h.Write(testData)
	result := h.Sum(nil)
	h.Reset()

	// Compare with known SHA3-512 hash
	ref := sha3.New512()
	ref.Write(testData)
	expected := ref.Sum(nil)

	if len(result) != len(expected) {
		return false
	}
	for i := range result {
		if result[i] != expected[i] {
			return false
		}
	}
	return true
}

// sortClaimsByDepth sorts claims by path depth (deepest first) to ensure
// child claims are processed before parent claims in recursive selective disclosure.
// This makes the VCTM claim order independent - users can specify claims in any order.
func sortClaimsByDepth(claims []Claim) []Claim {
	if len(claims) == 0 {
		return claims
	}

	// Create a copy to avoid modifying the original
	sorted := make([]Claim, len(claims))
	copy(sorted, claims)

	// Sort by path length (descending - deepest first)
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if len(sorted[i].Path) < len(sorted[j].Path) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	return sorted
}
