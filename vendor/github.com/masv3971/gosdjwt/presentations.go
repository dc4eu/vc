package gosdjwt

import (
	"fmt"
	"strings"
)

type Presentation interface {
	String() string
}

// EnvelopePresentation is the envelope presentation
type EnvelopePresentation struct {
	AUD   string `json:"aud"`
	IAT   int64  `json:"iat"`
	Nonce string `json:"nonce"`
	SDJWT string `json:"_sd_jwt"`
}

func (p EnvelopePresentation) String() string {
	return p.SDJWT
}

// JWSPresentation is the JWS presentation, RFC7515
type JWSPresentation struct {
	Payload     string   `json:"payload"`
	Protected   string   `json:"protected"`
	Signature   string   `json:"signature"`
	Disclosures []string `json:"disclosures"`
}

func (p JWSPresentation) String() string {
	return ""
}

// JWSPresentationWithKeyBinding is the JWS presentation with key binding
type JWSPresentationWithKeyBinding struct {
	JWSPresentation
	KeyBinding string `json:"key_binding"`
}

func (p JWSPresentationWithKeyBinding) String() string {
	return ""
}

// StandardPresentation is the standard presentation between Holder and Verifier but in serialized format
type StandardPresentation struct {
	JWT         string
	Disclosures []string
	KeyBinding  string
}

func (p StandardPresentation) String() string {
	t := p.JWT
	if p.Disclosures != nil {
		t += fmt.Sprintf("~%s~", strings.Join(p.Disclosures, "~"))
	}
	if p.KeyBinding != "" {
		t += fmt.Sprintf("%s", p.KeyBinding)
	}
	fmt.Println(t)
	return t
}
