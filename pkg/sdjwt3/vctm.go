package sdjwt3

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/PaesslerAG/jsonpath"
)

func (c *Claim) JSONPath() string {
	if c == nil || c.Path == nil {
		return ""
	}

	reply := "$."
	for _, path := range c.Path {
		reply += fmt.Sprintf("%s.", *path)
	}

	reply = strings.TrimRight(reply, ".")
	return reply
}

type VCTMJSONPath struct {
	Displayable map[string]string `json:"displayable"`
	AllClaims   []string          `json:"all_claims"`
}

func (v *VCTM) ClaimJSONPath() (*VCTMJSONPath, error) {
	if v.Claims == nil {
		return nil, fmt.Errorf("claims are nil")
	}

	reply := &VCTMJSONPath{
		Displayable: map[string]string{},
		AllClaims:   []string{},
	}

	for _, claim := range v.Claims {
		if claim.SVGID != "" {
			reply.Displayable[claim.SVGID] = claim.JSONPath()
		}
		reply.AllClaims = append(reply.AllClaims, claim.JSONPath())
	}

	return reply, nil
}

func Filter(documentData map[string]any, filter map[string]string) (map[string]any, error) {
	v := any(nil)

	b, err := json.Marshal(documentData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal document data: %w", err)
	}

	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("failed to unmarshal document data: %w", err)
	}

	reply := map[string]any{} // update with label etc. use struct

	for key, path := range filter {
		result, err := jsonpath.Get(path, v)
		if err != nil {
			return nil, fmt.Errorf("failed to get path %s", path)
		}

		reply[key] = result
	}

	return reply, nil
}
