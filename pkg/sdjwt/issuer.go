package sdjwt

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.step.sm/crypto/randutil"
)

// Instruction instructs how to build a SD-JWT
//type Instruction struct {
//	//Children       Instructions `json:"children,omitempty" yaml:"children,omitempty"`
//	SD             bool         `json:"sd,omitempty" yaml:"sd,omitempty"`
//	Salt           string       `json:"salt,omitempty" yaml:"salt,omitempty"`
//	Value          any          `json:"value,omitempty" yaml:"value,omitempty"`
//	Name           string       `json:"name,omitempty" yaml:"name,omitempty"`
//	DisclosureHash string       `json:"disclosure_hash,omitempty" yaml:"disclosure_hash,omitempty"`
//	ClaimHash      string       `json:"claim_hash,omitempty" yaml:"claim_hash,omitempty"`
//	Heritage       int          `json:"heritage" yaml:"heritage,omitempty"`
//	ID             string       `json:"id,omitempty" yaml:"id,omitempty"`
//	ParentNames    []string     `json:"parent_names,omitempty" yaml:"parent_names,omitempty"`
//	IsParent       bool         `json:"is_parent,omitempty" yaml:"is_parent,omitempty"`
//}

// DefaultClaims holds the default claims
//type DefaultClaims struct {
//	IAT int64  `json:"iat" default:"0"`
//	EXP int64  `json:"exp"`
//	NBF int64  `json:"nbf"`
//	ISS string `json:"iss"`
//}

// Disclosures is a map of disclosures
//type Disclosures map[string]*Disclosure

// ArrayHashes returns a string array of disclosure hashes
//func (d Disclosures) ArrayHashes() []string {
//	a := []string{}
//	for _, v := range d {
//		a = append(a, v.disclosureHash)
//	}
//	return a
//}

// SDJWT is a sd-jwt
type SDJWT struct {
	JWT         string
	Disclosures DisclosuresV2
	KeyBinding  string
}

var (
	newSalt = func() string {
		r, _ := randutil.ASCII(17)
		return base64.RawURLEncoding.EncodeToString([]byte(r))
	}
)

func newUUID() string {
	return uuid.NewString()
}

func hash(disclosureHash string) string {
	sha256Encoded := fmt.Sprintf("%x", sha256.Sum256([]byte(disclosureHash)))

	return base64.RawURLEncoding.EncodeToString([]byte(sha256Encoded))
}

func addToArray(key string, value any, storage jwt.MapClaims) {
	claim, ok := storage[key]
	if !ok {
		storage[key] = []any{value}
	} else {
		storage[key] = append(claim.([]any), value)
	}
}

func (i InstructionsV2) createSDJWT() (jwt.MapClaims, DisclosuresV2, error) {
	storage := jwt.MapClaims{}
	disclosures := DisclosuresV2{}
	if err := makeSDV2(i, storage, disclosures); err != nil {
		return nil, nil, err
	}
	return storage, disclosures, nil
}

func sign(claims jwt.MapClaims, signingMethod jwt.SigningMethod, signingKey any, config *Config) (string, error) {
	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["typ"] = "sd-jwt"

	if config.Header.Typ != "" {
		token.Header["typ"] = config.Header.Typ
	}

	if config.Header.Kid != "" {
		token.Header["kid"] = config.Header.Kid
	}

	return token.SignedString(signingKey)
}

//type Claim struct {
//	Disclosure bool
//	Value      string
//}

// ConfigHeader configs the header of the jwt
type ConfigHeader struct {
	Typ string
	Kid string
}

// Config configs sd-jwt-vc
type Config struct {
	ISS    string
	NBF    int64
	EXP    int64
	VCT    string
	Status string
	CNF    jwt.MapClaims
	Header ConfigHeader

	// SUB MAY be selectively disclosed
	SUB string
	// IAT MAY be selectively disclosed
	IAT int64
}

// SDJWT returns a signed SD-JWT with disclosures.
// Maybe this should return a more structured return of jwt and disclosures
func (i InstructionsV2) SDJWT(signingMethod jwt.SigningMethod, signingKey any, config *Config) (*SDJWT, error) {
	rawSDJWT, disclosures, err := i.createSDJWT()
	if err != nil {
		return nil, err
	}

	rawSDJWT["iss"] = config.ISS
	rawSDJWT["nbf"] = config.NBF
	rawSDJWT["exp"] = config.EXP
	rawSDJWT["cnf"] = config.CNF
	rawSDJWT["vct"] = config.VCT
	rawSDJWT["status"] = ""
	rawSDJWT["_sd_alg"] = "sha-256"

	signedJWT, err := sign(rawSDJWT, signingMethod, signingKey, config)
	if err != nil {
		return nil, err
	}

	sdjwt := &SDJWT{
		JWT:         signedJWT,
		Disclosures: disclosures,
	}

	//sdjwt := fmt.Sprintf("%s%s", signedJWT, disclosures.string())
	return sdjwt, nil
}
