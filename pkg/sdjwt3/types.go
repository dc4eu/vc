package sdjwt3

import (
	"encoding/base64"
	"hash"

	"encoding/json"
)

type Discloser struct {
	Salt      string `json:"-"`
	ClaimName string `json:"claim_name"`
	Value     any    `json:"value"`
}

// Hash returns the hash of the discloser and its base64 representation
func (d *Discloser) Hash(hasher hash.Hash) (string, string, []any, error) {
	disclosureArray := []any{d.Salt, d.ClaimName, d.Value}

	switch d.Value.(type) {
	case map[string]any:
		v := d.Value.(map[string]any)

		disclosureArray = []any{d.Salt, d.ClaimName, v}
	}

	disclosureBytes, err := json.Marshal(disclosureArray)
	if err != nil {
		return "", "", nil, err
	}

	selectiveDisclosure := base64.RawURLEncoding.EncodeToString(disclosureBytes)

	_, err = hasher.Write([]byte(selectiveDisclosure))
	if err != nil {
		return "", "", nil, err
	}

	hashed := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	return hashed, selectiveDisclosure, disclosureArray, nil
}

type CredentialCache struct {
	Claims     []Discloser    `json:"claims"`
	Credential map[string]any `json:"credential"`
}
