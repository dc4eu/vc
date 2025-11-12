package sdjwt3

type Discloser struct {
	Salt      string `json:"-"`
	ClaimName string `json:"claim_name"`
	Value     any    `json:"value"`
}

type CredentialCache struct {
	Claims     []Discloser    `json:"claims"`
	Credential map[string]any `json:"credential"`
}
