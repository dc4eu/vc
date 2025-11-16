package utils

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"vc/pkg/oauth2"
)

// ValidateRedirectURI validates a redirect URI against a list of allowed URIs.
// Returns true if the URI is in the allowed list (exact match required).
func ValidateRedirectURI(uri string, allowedURIs []string) bool {
	for _, allowedURI := range allowedURIs {
		if uri == allowedURI {
			return true
		}
	}
	return false
}

// ValidateRedirectURIFormat validates that a redirect URI conforms to OAuth 2.0 requirements.
// Per RFC 6749:
// - Must have a scheme
// - Must not contain a fragment
func ValidateRedirectURIFormat(uri string) error {
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid redirect_uri: %w", err)
	}

	if parsed.Scheme == "" {
		return fmt.Errorf("redirect_uri must have a scheme")
	}

	if parsed.Fragment != "" {
		return fmt.Errorf("redirect_uri must not contain a fragment")
	}

	return nil
}

// ValidateScopes validates that all requested scopes are in the allowed list.
// Returns true if all requested scopes are allowed.
func ValidateScopes(requestedScopes, allowedScopes []string) bool {
	for _, scope := range requestedScopes {
		if !contains(allowedScopes, scope) {
			return false
		}
	}
	return true
}

// ValidatePKCE validates the code verifier against the code challenge.
// Wraps the oauth2.ValidatePKCE function for consistency.
func ValidatePKCE(codeVerifier, codeChallenge, codeChallengeMethod string) error {
	return oauth2.ValidatePKCE(codeVerifier, codeChallenge, codeChallengeMethod)
}

// ValidateHTTPSURI validates that a URI uses HTTPS scheme and has proper format.
// Used for client metadata URIs (logo_uri, client_uri, policy_uri, tos_uri).
// Per RFC 7591 Section 2:
// - Must use HTTPS scheme
// - Must not contain a fragment
// - Must have a host
func ValidateHTTPSURI(uri, fieldName string) error {
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid %s URL: %w", fieldName, err)
	}

	if parsed.Scheme != "https" {
		return fmt.Errorf("%s must use https scheme", fieldName)
	}

	if parsed.Fragment != "" {
		return fmt.Errorf("%s must not contain a fragment", fieldName)
	}

	if parsed.Host == "" {
		return fmt.Errorf("%s must have a host", fieldName)
	}

	return nil
}

// ValidateURI validates a URI with SSRF (Server-Side Request Forgery) prevention.
// Blocks requests to:
// - Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
// - Loopback addresses (127.0.0.0/8, ::1)
// - Link-local addresses (169.254.0.0/16, fe80::/10)
// - localhost hostname
//
// When requireHTTPS is true, also enforces HTTPS scheme.
func ValidateURI(uri string, requireHTTPS bool) error {
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Enforce HTTPS if required
	if requireHTTPS && parsed.Scheme != "https" {
		return fmt.Errorf("URL must use https scheme")
	}

	// Check for localhost
	if strings.ToLower(parsed.Hostname()) == "localhost" {
		return fmt.Errorf("localhost URLs are not allowed")
	}

	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(parsed.Hostname())
	if err != nil {
		return fmt.Errorf("failed to resolve hostname: %w", err)
	}

	// Check each resolved IP address
	for _, ip := range ips {
		if err := validateIPAddress(ip); err != nil {
			return err
		}
	}

	return nil
}

// validateIPAddress checks if an IP address is in a blocked range
func validateIPAddress(ip net.IP) error {
	// Check for loopback (127.0.0.0/8, ::1)
	if ip.IsLoopback() {
		return fmt.Errorf("loopback addresses are not allowed")
	}

	// Check for link-local (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("link-local addresses are not allowed")
	}

	// Check for private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
	if isPrivateIP(ip) {
		return fmt.Errorf("private IP addresses are not allowed")
	}

	return nil
}

// isPrivateIP checks if an IP is in a private range
func isPrivateIP(ip net.IP) bool {
	// Private IPv4 ranges
	privateRanges := []string{
		"10.0.0.0/8",     // Class A private network
		"172.16.0.0/12",  // Class B private networks
		"192.168.0.0/16", // Class C private networks
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// contains checks if a slice contains a specific item
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
