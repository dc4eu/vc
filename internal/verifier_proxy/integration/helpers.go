package integration

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// PKCE helpers

// PKCEPair holds PKCE verifier and challenge
type PKCEPair struct {
	Verifier  string
	Challenge string
	Method    string
}

// GeneratePKCEPair generates a PKCE verifier and challenge
func GeneratePKCEPair() *PKCEPair {
	// Generate 43-character verifier (minimum length for PKCE)
	verifier := generateRandomString(86)[:43]

	// Compute S256 challenge
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return &PKCEPair{
		Verifier:  verifier,
		Challenge: challenge,
		Method:    "S256",
	}
}

// OIDCClientSimulator simulates an OIDC Relying Party
type OIDCClientSimulator struct {
	suite        *IntegrationSuite
	httpClient   *http.Client
	baseURL      string
	clientID     string
	clientSecret string
	redirectURI  string
}

// NewOIDCClientSimulator creates a new OIDC client simulator
func NewOIDCClientSimulator(suite *IntegrationSuite, clientID, clientSecret, redirectURI string) *OIDCClientSimulator {
	return &OIDCClientSimulator{
		suite:        suite,
		httpClient:   suite.GetHTTPClient(),
		baseURL:      suite.cfg.VerifierProxy.ExternalURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
	}
}

// AuthorizeParams holds parameters for authorization request
type AuthorizeParams struct {
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Display             string
	Prompt              string
}

// AuthorizeResponse holds the authorization response
type AuthorizeResponse struct {
	SessionID    string
	QRCodeData   string
	DeepLinkURL  string
	PollURL      string
	StatusCode   int
	Body         string
	ErrorCode    string
	ErrorDesc    string
}

// StartAuthorization initiates the authorization flow
func (c *OIDCClientSimulator) StartAuthorization(params AuthorizeParams) (*AuthorizeResponse, error) {
	// Build authorization query parameters
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", c.clientID)
	query.Set("redirect_uri", c.redirectURI)
	query.Set("scope", params.Scope)
	query.Set("state", params.State)
	query.Set("nonce", params.Nonce)

	if params.CodeChallenge != "" {
		query.Set("code_challenge", params.CodeChallenge)
		query.Set("code_challenge_method", params.CodeChallengeMethod)
	}
	if params.Display != "" {
		query.Set("display", params.Display)
	}
	if params.Prompt != "" {
		query.Set("prompt", params.Prompt)
	}

	// TODO: Make actual HTTP request when server is available
	// For now, return placeholder
	return &AuthorizeResponse{
		SessionID:  "session-" + generateRandomString(32),
		QRCodeData: "openid4vp://...",
		StatusCode: http.StatusOK,
	}, nil
}

// TokenParams holds parameters for token exchange
type TokenParams struct {
	GrantType    string
	Code         string
	CodeVerifier string
	RefreshToken string
}

// TokenResponse holds the token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope,omitempty"`
}

// ExchangeCodeForTokens exchanges authorization code for tokens
func (c *OIDCClientSimulator) ExchangeCodeForTokens(params TokenParams) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/token", c.baseURL)

	data := url.Values{}
	data.Set("grant_type", params.GrantType)
	data.Set("client_id", c.clientID)
	data.Set("redirect_uri", c.redirectURI)

	if params.Code != "" {
		data.Set("code", params.Code)
	}
	if params.CodeVerifier != "" {
		data.Set("code_verifier", params.CodeVerifier)
	}
	if params.RefreshToken != "" {
		data.Set("refresh_token", params.RefreshToken)
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add client authentication
	if c.clientSecret != "" {
		req.SetBasicAuth(c.clientID, c.clientSecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed: %d - %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// GetUserInfo retrieves user info using access token
func (c *OIDCClientSimulator) GetUserInfo(accessToken string) (map[string]any, error) {
	userInfoURL := fmt.Sprintf("%s/userinfo", c.baseURL)

	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed: %d - %s", resp.StatusCode, string(body))
	}

	var userInfo map[string]any
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
}

// WalletSimulator simulates an EU Digital Identity Wallet
type WalletSimulator struct {
	suite      *IntegrationSuite
	httpClient *http.Client
	walletID   string
	credentials map[string]any
}

// NewWalletSimulator creates a new wallet simulator
func NewWalletSimulator(suite *IntegrationSuite, walletID string) *WalletSimulator {
	return &WalletSimulator{
		suite:      suite,
		httpClient: suite.GetHTTPClient(),
		walletID:   walletID,
		credentials: map[string]any{
			"pid": map[string]any{
				"given_name":  "John",
				"family_name": "Doe",
				"birthdate":   "1990-01-01",
				"age_over_18": true,
				"nationality": "SE",
			},
			"profile": map[string]any{
				"given_name":  "John",
				"family_name": "Doe",
				"nickname":    "Johnny",
			},
		},
	}
}

// GetRequestObject retrieves the request object for a session
func (w *WalletSimulator) GetRequestObject(sessionID string, verifierURL string) (string, error) {
	reqObjURL := fmt.Sprintf("%s/verification/request-object/%s", verifierURL, sessionID)

	resp, err := w.httpClient.Get(reqObjURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request object failed: %d - %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

// CreateVPToken creates a mock VP token in SD-JWT format for testing
func (w *WalletSimulator) CreateVPToken(nonce, audience string) (string, error) {
	// Create a simple JWT payload with minimal claims
	// Note: We use uncommon claim names to avoid overwriting OIDC ID token claims
	claims := map[string]any{
		"wallet_iss": w.walletID,  // Use wallet_iss instead of iss to avoid conflict
		"wallet_sub": w.walletID,  // Use wallet_sub instead of sub
		"wallet_aud": audience,    // Use wallet_aud instead of aud
		"exp":        time.Now().Add(10 * time.Minute).Unix(),
		"iat":        time.Now().Add(10 * time.Minute).Unix(),
		"vct":        "eu.europa.ec.eudi.pid.1", // Verifiable Credential Type
		// In real SD-JWT, _sd array would contain hashes of disclosures
		"_sd": []string{"dummy-hash"},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	
	// Sign with test secret (in real scenario, would use wallet's private key)
	tokenString, err := token.SignedString([]byte("test-wallet-secret"))
	if err != nil {
		return "", err
	}

	// Create a minimal disclosure: [<salt>, <claim-name>, <claim-value>]
	disclosure := []any{
		"_salt123",      // Salt for disclosure
		"given_name",    // Claim name
		"John",          // Claim value
	}
	disclosureJSON, _ := json.Marshal(disclosure)
	disclosureB64 := base64.RawURLEncoding.EncodeToString(disclosureJSON)

	// Format as SD-JWT: <jwt>~<disclosure>~<key_binding>
	// For testing: jwt~disclosure~  (empty key binding)
	sdJWT := fmt.Sprintf("%s~%s~", tokenString, disclosureB64)
	
	return sdJWT, nil
}

// SubmitPresentation submits VP token to verifier proxy
func (w *WalletSimulator) SubmitPresentation(sessionID, vpToken, verifierURL string) error {
	directPostURL := fmt.Sprintf("%s/verification/direct_post", verifierURL)

	data := url.Values{}
	data.Set("vp_token", vpToken)
	data.Set("state", sessionID)
	data.Set("presentation_submission", `{"id":"submission-1","definition_id":"pd-1"}`)

	req, err := http.NewRequest("POST", directPostURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("direct post failed: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

// ParseIDToken parses and validates an ID token (basic validation for testing)
func ParseIDToken(tokenString string) (map[string]any, error) {
	// Parse without validation for testing
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		result := make(map[string]any)
		for k, v := range claims {
			result[k] = v
		}
		return result, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// AssertIDToken validates ID token claims
func AssertIDToken(tokenString string, expectedNonce string) (map[string]any, error) {
	claims, err := ParseIDToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Verify required claims
	if claims["sub"] == nil || claims["sub"] == "" {
		return nil, fmt.Errorf("ID token must have 'sub' claim")
	}
	if claims["aud"] == nil || claims["aud"] == "" {
		return nil, fmt.Errorf("ID token must have 'aud' claim")
	}
	if claims["exp"] == nil {
		return nil, fmt.Errorf("ID token must have 'exp' claim")
	}
	if claims["iat"] == nil {
		return nil, fmt.Errorf("ID token must have 'iat' claim")
	}

	if expectedNonce != "" && claims["nonce"] != expectedNonce {
		return nil, fmt.Errorf("ID token nonce must match expected: %s, got: %v", expectedNonce, claims["nonce"])
	}

	return claims, nil
}
