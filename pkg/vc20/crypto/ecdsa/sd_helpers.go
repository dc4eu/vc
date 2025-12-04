package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

func parseNQuads(nquads string) []string {
	if nquads == "" {
		return []string{}
	}
	lines := strings.Split(nquads, "\n")
	var result []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			result = append(result, line)
		}
	}
	return result
}

func parseQuadComponents(quad string) (string, string, string, string) {
	// Very basic N-Quad parser
	// Assumes canonical format (spaces separate components)
	// Subject Predicate Object Graph .
	// Note: Object can be a string with spaces.
	// But in canonical form, strings are escaped.
	// We can use regex or simple splitting if we are careful.

	// Better: use a proper RDF parser if available, but we are working with strings here.
	// For grouping, we just need to identify blank nodes.

	parts := strings.SplitN(quad, " ", 3)
	if len(parts) < 3 {
		return "", "", "", ""
	}
	s := parts[0]
	p := parts[1]
	rest := parts[2]

	// Object is tricky. It ends with " ." or " <graph> ."
	// But since we only care about blank nodes which are _:..., they don't contain spaces.
	// If object is a literal, it starts with ".

	var o string
	// If rest starts with ", parse until end of string
	// If rest starts with < or _:, parse until space

	if strings.HasPrefix(rest, "\"") {
		// Literal. Find the end of the literal.
		// This is hard without full parsing.
		// But we only need to check if it is a blank node.
		// Literals are NOT blank nodes.
		o = "LITERAL" // Placeholder
	} else {
		oParts := strings.SplitN(rest, " ", 2)
		o = oParts[0]
	}

	return s, p, o, ""
}

func skolemizeQuad(quad string, key []byte) string {
	// Replace all _:... with _:HMAC(...)
	// We need to find all occurrences of _:([a-zA-Z0-9]+)
	// and replace them.

	re := regexp.MustCompile(`_:[a-zA-Z0-9\-_]+`)
	return re.ReplaceAllStringFunc(quad, func(match string) string {
		// match is _:label
		label := match[2:]
		h := hmacSha256(key, []byte(label))
		// Encode h as base64url or hex? Spec says "multibase base58-btc" usually for IDs?
		// Spec: "The identifier is the base64url-encoded HMAC."
		encoded := base64.URLEncoding.EncodeToString(h)
		// Remove padding?
		encoded = strings.TrimRight(encoded, "=")
		return "_:" + encoded
	})
}

func hmacSha256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func serializeSignature(r, s *big.Int, bits int) []byte {
	keyBytes := (bits + 7) / 8
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	signature := make([]byte, 2*keyBytes)
	copy(signature[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(signature[2*keyBytes-len(sBytes):], sBytes)
	return signature
}

func ellipticMarshal(pub ecdsa.PublicKey) []byte {
	// Use standard uncompressed point serialization
	// 0x04 || x || y
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

func verifySignature(key *ecdsa.PublicKey, hash, signature []byte) bool {
	keyBytes := (key.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*keyBytes {
		return false
	}
	r := new(big.Int).SetBytes(signature[:keyBytes])
	s := new(big.Int).SetBytes(signature[keyBytes:])
	return ecdsa.Verify(key, hash, r, s)
}

func replaceURNs(data any) {
	if m, ok := data.(map[string]any); ok {
		for k, v := range m {
			if s, ok := v.(string); ok {
				if strings.HasPrefix(s, "urn:bn:") {
					m[k] = "_:" + s[7:]
				}
			} else {
				replaceURNs(v)
			}
		}
	} else if list, ok := data.([]any); ok {
		for i, item := range list {
			if s, ok := item.(string); ok {
				if strings.HasPrefix(s, "urn:bn:") {
					list[i] = "_:" + s[7:]
				}
			} else {
				replaceURNs(item)
			}
		}
	}
}

func replaceLabelsWithURNs(data any, labelMap map[string]string) {
	if m, ok := data.(map[string]any); ok {
		for k, v := range m {
			if s, ok := v.(string); ok {
				if strings.HasPrefix(s, "_:") {
					label := s[2:]
					if hmac, ok := labelMap[label]; ok {
						m[k] = fmt.Sprintf("urn:bn:%s", hmac)
					}
				}
			} else {
				replaceLabelsWithURNs(v, labelMap)
			}
		}
	} else if list, ok := data.([]any); ok {
		for i, item := range list {
			if s, ok := item.(string); ok {
				if strings.HasPrefix(s, "_:") {
					label := s[2:]
					if hmac, ok := labelMap[label]; ok {
						list[i] = fmt.Sprintf("urn:bn:%s", hmac)
					}
				}
			} else {
				replaceLabelsWithURNs(item, labelMap)
			}
		}
	}
}

func replaceURNsInNQuads(nquads string) string {
	// Replace <urn:bn:HMAC> with _:HMAC
	re := regexp.MustCompile(`<urn:bn:([^>]+)>`)
	return re.ReplaceAllString(nquads, "_:$1")
}

func removeProof(data any) {
	if m, ok := data.(map[string]any); ok {
		delete(m, "proof")
		delete(m, "https://w3id.org/security#proof")
		delete(m, "https://www.w3.org/ns/credentials#proof")

		for _, v := range m {
			removeProof(v)
		}
	} else if list, ok := data.([]any); ok {
		for _, item := range list {
			removeProof(item)
		}
	}
}
