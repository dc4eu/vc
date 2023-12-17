package gosdjwt

import (
	"fmt"
	"strings"
)

type Presentation interface {
	String() string
}

// PresentationEnvelope is the envelope presentation
type PresentationEnvelope struct {
	AUD   string `json:"aud"`
	IAT   int64  `json:"iat"`
	Nonce string `json:"nonce"`
	SDJWT string `json:"_sd_jwt"`
}

func (p PresentationEnvelope) String() string {
	return p.SDJWT
}

// PresentationJWS is the JWS presentation, RFC7515
type PresentationJWS struct {
	Payload     string   `json:"payload"`
	Protected   string   `json:"protected"`
	Signature   string   `json:"signature"`
	Disclosures []string `json:"disclosures"`
}

func (p PresentationJWS) String() string {
	return ""
}

// PresentationJWSWithKeyBinding is the JWS presentation with key binding
type PresentationJWSWithKeyBinding struct {
	PresentationJWS
	KeyBinding string `json:"key_binding"`
}

func (p PresentationJWSWithKeyBinding) String() string {
	return ""
}

// PresentationFlat is the standard presentation between Holder and Verifier but in serialized format
type PresentationFlat struct {
	JWT         string
	Disclosures []string
	KeyBinding  string
}

func (p *SDJWT) String() string {
	t := p.JWT
	if p.Disclosures != nil {
		t += fmt.Sprintf("~%s~", strings.Join(p.Disclosures.ArrayHashes(), "~"))
	}
	if p.KeyBinding != "" {
		t += fmt.Sprintf("%s", p.KeyBinding)
	}
	fmt.Println(t)
	return t
}
