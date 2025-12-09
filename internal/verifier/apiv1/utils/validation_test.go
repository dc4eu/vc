package utils

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateRedirectURI tests the redirect URI validation
func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		allowedURIs []string
		expected    bool
	}{
		{
			name:        "exact match",
			uri:         "https://example.com/callback",
			allowedURIs: []string{"https://example.com/callback"},
			expected:    true,
		},
		{
			name:        "one of multiple allowed",
			uri:         "https://example.com/callback",
			allowedURIs: []string{"https://other.com/callback", "https://example.com/callback"},
			expected:    true,
		},
		{
			name:        "not in allowed list",
			uri:         "https://malicious.com/callback",
			allowedURIs: []string{"https://example.com/callback"},
			expected:    false,
		},
		{
			name:        "empty allowed list",
			uri:         "https://example.com/callback",
			allowedURIs: []string{},
			expected:    false,
		},
		{
			name:        "localhost callback",
			uri:         "http://localhost:8080/callback",
			allowedURIs: []string{"http://localhost:8080/callback"},
			expected:    true,
		},
		{
			name:        "partial match not allowed",
			uri:         "https://example.com/callback/extra",
			allowedURIs: []string{"https://example.com/callback"},
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateRedirectURI(tt.uri, tt.allowedURIs)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestValidateRedirectURIFormat tests redirect URI format validation
func TestValidateRedirectURIFormat(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid https URI",
			uri:     "https://example.com/callback",
			wantErr: false,
		},
		{
			name:    "valid http URI",
			uri:     "http://example.com/callback",
			wantErr: false,
		},
		{
			name:    "valid custom scheme",
			uri:     "myapp://callback",
			wantErr: false,
		},
		{
			name:    "missing scheme",
			uri:     "example.com/callback",
			wantErr: true,
			errMsg:  "must have a scheme",
		},
		{
			name:    "URI with fragment",
			uri:     "https://example.com/callback#section",
			wantErr: true,
			errMsg:  "must not contain a fragment",
		},
		{
			name:    "localhost with port",
			uri:     "http://localhost:8080/callback",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURIFormat(tt.uri)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateScopes tests scope validation
func TestValidateScopes(t *testing.T) {
	tests := []struct {
		name            string
		requestedScopes []string
		allowedScopes   []string
		expected        bool
	}{
		{
			name:            "all scopes allowed",
			requestedScopes: []string{"openid", "profile"},
			allowedScopes:   []string{"openid", "profile", "email"},
			expected:        true,
		},
		{
			name:            "one scope not allowed",
			requestedScopes: []string{"openid", "admin"},
			allowedScopes:   []string{"openid", "profile", "email"},
			expected:        false,
		},
		{
			name:            "empty requested scopes",
			requestedScopes: []string{},
			allowedScopes:   []string{"openid", "profile"},
			expected:        true,
		},
		{
			name:            "empty allowed scopes",
			requestedScopes: []string{"openid"},
			allowedScopes:   []string{},
			expected:        false,
		},
		{
			name:            "exact match",
			requestedScopes: []string{"openid"},
			allowedScopes:   []string{"openid"},
			expected:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateScopes(tt.requestedScopes, tt.allowedScopes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestValidatePKCE tests PKCE validation
func TestValidatePKCE(t *testing.T) {
	tests := []struct {
		name                string
		codeVerifier        string
		codeChallenge       string
		codeChallengeMethod string
		wantErr             bool
	}{
		{
			name:                "valid S256",
			codeVerifier:        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			wantErr:             false,
		},
		{
			name:                "invalid S256 - wrong verifier",
			codeVerifier:        "wrongverifier123456789012345678901234567890123",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			wantErr:             true,
		},
		{
			name:                "plain method",
			codeVerifier:        "test-verifier",
			codeChallenge:       "test-verifier",
			codeChallengeMethod: "plain",
			wantErr:             false,
		},
		{
			name:                "plain method - mismatch",
			codeVerifier:        "test-verifier",
			codeChallenge:       "different-challenge",
			codeChallengeMethod: "plain",
			wantErr:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePKCE(tt.codeVerifier, tt.codeChallenge, tt.codeChallengeMethod)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateHTTPSURI tests HTTPS URI validation
func TestValidateHTTPSURI(t *testing.T) {
	tests := []struct {
		name      string
		uri       string
		fieldName string
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "valid https URI",
			uri:       "https://example.com/logo.png",
			fieldName: "logo_uri",
			wantErr:   false,
		},
		{
			name:      "http not allowed",
			uri:       "http://example.com/logo.png",
			fieldName: "logo_uri",
			wantErr:   true,
			errMsg:    "must use https scheme",
		},
		{
			name:      "missing scheme",
			uri:       "example.com/logo.png",
			fieldName: "logo_uri",
			wantErr:   true,
			errMsg:    "must use https scheme",
		},
		{
			name:      "with fragment",
			uri:       "https://example.com/page#section",
			fieldName: "client_uri",
			wantErr:   true,
			errMsg:    "must not contain a fragment",
		},
		{
			name:      "missing host",
			uri:       "https:///path",
			fieldName: "policy_uri",
			wantErr:   true,
			errMsg:    "must have a host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHTTPSURI(tt.uri, tt.fieldName)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestContains tests the contains helper function
func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		expected bool
	}{
		{
			name:     "item exists",
			slice:    []string{"a", "b", "c"},
			item:     "b",
			expected: true,
		},
		{
			name:     "item not exists",
			slice:    []string{"a", "b", "c"},
			item:     "d",
			expected: false,
		},
		{
			name:     "empty slice",
			slice:    []string{},
			item:     "a",
			expected: false,
		},
		{
			name:     "first element",
			slice:    []string{"a", "b", "c"},
			item:     "a",
			expected: true,
		},
		{
			name:     "last element",
			slice:    []string{"a", "b", "c"},
			item:     "c",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.slice, tt.item)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsPrivateIP tests private IP detection
func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "Class A private",
			ip:       "10.0.0.1",
			expected: true,
		},
		{
			name:     "Class B private",
			ip:       "172.16.0.1",
			expected: true,
		},
		{
			name:     "Class C private",
			ip:       "192.168.1.1",
			expected: true,
		},
		{
			name:     "Public IP",
			ip:       "8.8.8.8",
			expected: false,
		},
		{
			name:     "Edge of Class B range",
			ip:       "172.31.255.255",
			expected: true,
		},
		{
			name:     "Outside Class B range",
			ip:       "172.32.0.1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := parseIP(tt.ip)
			if ip != nil {
				result := isPrivateIP(ip)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// parseIP is a helper for testing - simple IPv4 parser
func parseIP(s string) []byte {
	var ip [4]byte
	var parts [4]int

	// Simple IPv4 parser for testing
	count := 0
	num := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			num = num*10 + int(c-'0')
		} else if c == '.' {
			parts[count] = num
			count++
			num = 0
		}
	}
	parts[count] = num

	if count == 3 {
		ip[0] = byte(parts[0])
		ip[1] = byte(parts[1])
		ip[2] = byte(parts[2])
		ip[3] = byte(parts[3])
		return ip[:]
	}
	return nil
}

// TestValidateURI tests the ValidateURI function
func TestValidateURI(t *testing.T) {
	tests := []struct {
		name         string
		uri          string
		requireHTTPS bool
		wantErr      bool
	}{
		{
			name:         "valid HTTPS URI",
			uri:          "https://example.com/path",
			requireHTTPS: true,
			wantErr:      false,
		},
		{
			name:         "HTTP when HTTPS required",
			uri:          "http://example.com/path",
			requireHTTPS: true,
			wantErr:      true,
		},
		{
			name:         "HTTP when HTTPS not required",
			uri:          "http://example.com/path",
			requireHTTPS: false,
			wantErr:      false,
		},
		{
			name:         "localhost blocked by SSRF check",
			uri:          "https://localhost/path",
			requireHTTPS: true,
			wantErr:      true,
		},
		{
			name:         "missing scheme",
			uri:          "example.com/path",
			requireHTTPS: false,
			wantErr:      true,
		},
		{
			name:         "URI with fragment blocked",
			uri:          "https://example.com/path#fragment",
			requireHTTPS: true,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURI(tt.uri, tt.requireHTTPS)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateIPAddress tests the validateIPAddress function
func TestValidateIPAddress(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "public IP allowed",
			ip:      "8.8.8.8",
			wantErr: false,
		},
		{
			name:    "loopback blocked",
			ip:      "127.0.0.1",
			wantErr: true,
			errMsg:  "loopback",
		},
		{
			name:    "private Class A blocked",
			ip:      "10.0.0.1",
			wantErr: true,
			errMsg:  "private",
		},
		{
			name:    "private Class B blocked",
			ip:      "172.16.0.1",
			wantErr: true,
			errMsg:  "private",
		},
		{
			name:    "private Class C blocked",
			ip:      "192.168.1.1",
			wantErr: true,
			errMsg:  "private",
		},
		{
			name:    "link-local blocked",
			ip:      "169.254.1.1",
			wantErr: true,
			errMsg:  "link-local",
		},
		{
			name:    "public IP 1.1.1.1 allowed",
			ip:      "1.1.1.1",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "failed to parse test IP")

			err := validateIPAddress(ip)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestCheckSSRF tests the checkSSRF function
func TestCheckSSRF(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		{
			name:     "localhost blocked",
			hostname: "localhost",
			wantErr:  true,
		},
		{
			name:     "LOCALHOST blocked (case insensitive)",
			hostname: "LOCALHOST",
			wantErr:  true,
		},
		{
			name:     "valid public hostname",
			hostname: "example.com",
			wantErr:  false,
		},
		{
			name:     "google.com allowed",
			hostname: "google.com",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSSRF(tt.hostname)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
