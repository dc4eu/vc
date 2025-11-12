package sdjwt3

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// SplitToken splits into header, body, signature, selective disclosure, keybinding, or error
func SplitToken(token string) (string, string, string, []string, []string, error) {
	if token == "" {
		return "", "", "", nil, nil, errors.New("empty token")
	}

	parts := strings.Split(token, "~")
	sdToken := parts[0]
	header := strings.Split(sdToken, ".")[0]
	body := strings.Split(sdToken, ".")[1]
	signature := strings.Split(sdToken, ".")[2]

	selectiveDisclosure := parts[1 : len(parts)-1]

	keybinding := parts[len(parts)-1:]
	keybindingList := strings.Split(keybinding[0], ".")
	if slices.Contains(keybindingList, "") {
		return header, body, signature, selectiveDisclosure, nil, nil
	}

	return header, body, signature, selectiveDisclosure, keybindingList, nil
}

// Base64Decode decodes a base64 string to a string
func Base64Decode(s string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// Unmarshal unmarshal a string to a map
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

// Construct constructs a credential from a given credential string. Remember this is nasty code:
// * it does not validate the credential
// * it does not validate the keybinding
// * it does only support selective disclosure in the top _sd array
func Construct(ctx context.Context, credential string) (map[string]any, error) {
	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	if credential == "" {
		return nil, errors.New("empty credential")
	}

	_, body, _, sd, _, err := SplitToken(credential)
	if err != nil {
		return nil, err
	}

	fmt.Println("sd:", sd)

	b, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, err
	}

	cred, err := Unmarshal(string(b))
	if err != nil {
		return nil, err
	}
	if sd == nil {
		return cred, nil
	}

	for _, sdItem := range sd {
		s := sha256.Sum256([]byte(sdItem))
		b64 := base64.RawURLEncoding.EncodeToString(s[:])
		disclosures, ok := cred["_sd"].([]any)
		if !ok {
			return nil, errors.New("invalid _sd field in credential")
		}
		if slices.Contains(disclosures, any(b64)) {
			index := slices.Index(disclosures, any(b64))
			if index >= 0 {
				// Remove the selective disclosure item from the credential
				cred["_sd"] = slices.Delete(disclosures, index, index+1)

				// add attribute to the credential

				sdDecoded, err := base64.RawURLEncoding.DecodeString(sdItem)
				if err != nil {
					return nil, fmt.Errorf("failed to decode selective disclosure item: %w", err)
				}

				sdDeconstruct := []string{}
				if err := json.Unmarshal(sdDecoded, &sdDeconstruct); err != nil {
					return nil, fmt.Errorf("failed to unmarshal selective disclosure item: %w", err)
				}

				sdKey := sdDeconstruct[1]
				sdValue := sdDeconstruct[2]

				cred[sdKey] = sdValue

			}
		}
	}

	j, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return nil, err
	}
	fmt.Println("Unmarshaled Credential:", string(j))

	fmt.Println("Credential:", cred["given_name"])

	return cred, nil
}

// DiscloserParse parses a selective disclosure string into a Discloser struct
func DiscloserParse(ctx context.Context, sd string) (*Discloser, error) {
	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	if sd == "" {
		return nil, errors.New("empty selective disclosure")
	}

	b, err := base64.RawURLEncoding.DecodeString(sd)
	if err != nil {
		return nil, err
	}

	sdDeconstruct := []any{}
	if err := json.Unmarshal(b, &sdDeconstruct); err != nil {
		return nil, fmt.Errorf("failed to unmarshal selective disclosure item: %w", err)
	}

	reply := &Discloser{
		Salt:      sdDeconstruct[0].(string),
		ClaimName: sdDeconstruct[1].(string),
		Value:     sdDeconstruct[2],
	}

	return reply, nil
}

// CredentialParser parses a credential string into a map[string]any with disclosed claims
func CredentialParser(ctx context.Context, token string) (map[string]any, error) {
	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	_, body, _, sd, _, err := SplitToken(token)
	if err != nil {
		return nil, err
	}

	b, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, err
	}

	cred, err := Unmarshal(string(b))
	if err != nil {
		return nil, err
	}

	claims, err := json.Marshal(cred["_sd"])
	if err != nil {
		return nil, err
	}
	sdClaims := []string{}
	if err := json.Unmarshal(claims, &sdClaims); err != nil {
		return nil, err
	}

	for _, sdItem := range sd {
		discloser, err := DiscloserParse(ctx, sdItem)
		if err != nil {
			return nil, err
		}
		s := sha256.Sum256([]byte(sdItem))
		b64 := base64.RawURLEncoding.EncodeToString(s[:])

		if !slices.Contains(sdClaims, b64) {
			continue
		}

		cred[discloser.ClaimName] = discloser.Value

	}

	delete(cred, "_sd")
	delete(cred, "_sd_alg")
	return cred, nil
}
