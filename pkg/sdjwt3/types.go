package sdjwt3

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"encoding/json"
)

type Discloser struct {
	Salt      string `json:"-"`
	ClaimName string `json:"claim_name"`
	Value     any    `json:"value"`
}

// Hash returns the hash of the discloser and its base64 representation
func (d *Discloser) Hash() (string, string, []any, error) {
	fmt.Println("value", d.Value)
	t := []any{d.Salt, d.ClaimName, d.Value}

	b, err := json.Marshal(t)
	if err != nil {
		return "", "", nil, err
	}

	selectiveDisclosure := base64.RawURLEncoding.EncodeToString(b)

	s := sha256.Sum256(b)

	b64 := base64.RawURLEncoding.EncodeToString(s[:])

	return b64, selectiveDisclosure, t, nil
}

type CredentialCache struct {
	Claims     []Discloser    `json:"claims"`
	Credential map[string]any `json:"credential"`
}
