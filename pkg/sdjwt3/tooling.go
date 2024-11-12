package sdjwt3

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// SplitToken splits into header, body, signature, selective disclosure, or error
func SplitToken(token string) (string, string, string, []string, error) {
	if token == "" {
		return "", "", "", nil, errors.New("empty token")
	}

	parts := strings.Split(token, ".")
	header := parts[0]
	body := parts[1]

	footer := strings.Split(parts[2], "~")
	signature := footer[0]

	selectiveDisclosure := footer[1 : len(footer)-1]

	return header, body, signature, selectiveDisclosure, nil
}

// Base64Decode decodes a base64 string to a string
func Base64Decode(s string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// Unmarshal unmarshals a string to a map
func Unmarshal(s string) (map[string]any, error) {
	if s == "" {
		return nil, errors.New("empty input")
	}

	reply := map[string]any{}
	if err := json.Unmarshal([]byte(s), &reply); err != nil {
		return nil, err
	}

	return reply, nil
}

func selectiveDisclosureUniq(selectiveDisclosures []string) bool {
	uniq := make(map[string]bool)
	for _, v := range selectiveDisclosures {
		if _, found := uniq[v]; found {
			return false
		}
		uniq[v] = true
	}
	return true
}
