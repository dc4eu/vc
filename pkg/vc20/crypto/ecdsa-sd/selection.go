//go:build vc20

package ecdsasd

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// JSONPointer represents a JSON Pointer as defined in RFC 6901
type JSONPointer string

// SelectionOptions configures selective disclosure behavior
type SelectionOptions struct {
	// MandatoryPointers are JSON Pointers that MUST always be disclosed
	MandatoryPointers []JSONPointer
	// SelectivePointers are JSON Pointers that MAY be selectively disclosed
	SelectivePointers []JSONPointer
}

// ApplyJSONPointer retrieves a value from a JSON document using a JSON Pointer.
// Implements RFC 6901: https://tools.ietf.org/html/rfc6901
func ApplyJSONPointer(doc interface{}, pointer JSONPointer) (interface{}, error) {
	if pointer == "" {
		return doc, nil
	}

	// Remove leading slash
	pointerStr := string(pointer)
	if !strings.HasPrefix(pointerStr, "/") {
		return nil, fmt.Errorf("invalid JSON Pointer: must start with '/', got '%s'", pointerStr)
	}
	pointerStr = pointerStr[1:]

	// Split into tokens
	tokens := strings.Split(pointerStr, "/")

	current := doc
	for i, token := range tokens {
		// Unescape special characters per RFC 6901
		token = unescapeJSONPointerToken(token)

		switch v := current.(type) {
		case map[string]interface{}:
			// Object traversal
			val, ok := v[token]
			if !ok {
				return nil, fmt.Errorf("JSON Pointer '%s' not found at token '%s' (index %d)", pointer, token, i)
			}
			current = val

		case []interface{}:
			// Array traversal
			idx, err := strconv.Atoi(token)
			if err != nil {
				return nil, fmt.Errorf("invalid array index '%s' in JSON Pointer '%s': %w", token, pointer, err)
			}
			if idx < 0 || idx >= len(v) {
				return nil, fmt.Errorf("array index %d out of bounds (length %d) in JSON Pointer '%s'", idx, len(v), pointer)
			}
			current = v[idx]

		default:
			return nil, fmt.Errorf("cannot traverse into %T at token '%s' in JSON Pointer '%s'", current, token, pointer)
		}
	}

	return current, nil
}

// unescapeJSONPointerToken unescapes special characters in a JSON Pointer token.
// Per RFC 6901: "~1" -> "/" and "~0" -> "~"
func unescapeJSONPointerToken(token string) string {
	// Order matters: unescape ~1 before ~0
	token = strings.ReplaceAll(token, "~1", "/")
	token = strings.ReplaceAll(token, "~0", "~")
	return token
}

// escapeJSONPointerToken escapes special characters in a JSON Pointer token.
// Per RFC 6901: "~" -> "~0" and "/" -> "~1"
func escapeJSONPointerToken(token string) string {
	// Order matters: escape ~ before /
	token = strings.ReplaceAll(token, "~", "~0")
	token = strings.ReplaceAll(token, "/", "~1")
	return token
}

// ValidateJSONPointer validates that a string is a valid JSON Pointer
func ValidateJSONPointer(pointer JSONPointer) error {
	if pointer == "" {
		return nil // Empty string is valid (references whole document)
	}

	pointerStr := string(pointer)
	if !strings.HasPrefix(pointerStr, "/") {
		return fmt.Errorf("invalid JSON Pointer: must start with '/' or be empty, got '%s'", pointerStr)
	}

	// Check for invalid escape sequences
	tokens := strings.Split(pointerStr[1:], "/")
	for i, token := range tokens {
		// Check for invalid ~x sequences (only ~0 and ~1 are valid)
		for j := 0; j < len(token); j++ {
			if token[j] == '~' {
				if j+1 >= len(token) {
					return fmt.Errorf("invalid escape sequence at end of token %d", i)
				}
				next := token[j+1]
				if next != '0' && next != '1' {
					return fmt.Errorf("invalid escape sequence '~%c' in token %d (only ~0 and ~1 allowed)", next, i)
				}
			}
		}
	}

	return nil
}

// SelectFields applies selective disclosure to a JSON document.
// Returns a new document containing only the selected fields.
func SelectFields(doc interface{}, pointers []JSONPointer) (interface{}, error) {
	if len(pointers) == 0 {
		return nil, fmt.Errorf("no pointers specified for selection")
	}

	// Parse document as JSON map
	var docMap map[string]interface{}
	switch v := doc.(type) {
	case map[string]interface{}:
		docMap = v
	case []byte:
		if err := json.Unmarshal(v, &docMap); err != nil {
			return nil, fmt.Errorf("failed to parse JSON document: %w", err)
		}
	case string:
		if err := json.Unmarshal([]byte(v), &docMap); err != nil {
			return nil, fmt.Errorf("failed to parse JSON document: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported document type: %T", doc)
	}

	// Create result map with selected fields
	result := make(map[string]interface{})

	for _, pointer := range pointers {
		if err := ValidateJSONPointer(pointer); err != nil {
			return nil, fmt.Errorf("invalid pointer '%s': %w", pointer, err)
		}

		// Apply pointer to get value
		value, err := ApplyJSONPointer(docMap, pointer)
		if err != nil {
			return nil, fmt.Errorf("failed to apply pointer '%s': %w", pointer, err)
		}

		// Set value in result using pointer path
		if err := setValueAtPointer(result, pointer, value); err != nil {
			return nil, fmt.Errorf("failed to set value for pointer '%s': %w", pointer, err)
		}
	}

	return result, nil
}

// setValueAtPointer sets a value in a map at the location specified by a JSON Pointer
func setValueAtPointer(target map[string]interface{}, pointer JSONPointer, value interface{}) error {
	if pointer == "" {
		return fmt.Errorf("cannot set root value")
	}

	pointerStr := string(pointer)
	if !strings.HasPrefix(pointerStr, "/") {
		return fmt.Errorf("invalid JSON Pointer: must start with '/'")
	}
	pointerStr = pointerStr[1:]

	tokens := strings.Split(pointerStr, "/")
	if len(tokens) == 0 {
		return fmt.Errorf("empty pointer path")
	}

	// Navigate to parent
	current := interface{}(target)
	for i := 0; i < len(tokens)-1; i++ {
		token := unescapeJSONPointerToken(tokens[i])

		switch v := current.(type) {
		case map[string]interface{}:
			// Create intermediate object if it doesn't exist
			if _, ok := v[token]; !ok {
				v[token] = make(map[string]interface{})
			}
			current = v[token]
		default:
			return fmt.Errorf("cannot navigate through non-object at token '%s'", token)
		}
	}

	// Set final value
	lastToken := unescapeJSONPointerToken(tokens[len(tokens)-1])
	if m, ok := current.(map[string]interface{}); ok {
		m[lastToken] = value
		return nil
	}

	return fmt.Errorf("cannot set value in non-object")
}

// IsMandatory checks if a JSON Pointer is in the mandatory list
func IsMandatory(pointer JSONPointer, mandatoryPointers []JSONPointer) bool {
	for _, mp := range mandatoryPointers {
		if pointer == mp {
			return true
		}
	}
	return false
}

// FilterPointers filters a list of pointers, removing those that are mandatory
func FilterPointers(pointers []JSONPointer, mandatoryPointers []JSONPointer) []JSONPointer {
	filtered := make([]JSONPointer, 0, len(pointers))
	for _, p := range pointers {
		if !IsMandatory(p, mandatoryPointers) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// MergePointers merges mandatory and selective pointers, removing duplicates
func MergePointers(mandatoryPointers, selectivePointers []JSONPointer) []JSONPointer {
	seen := make(map[JSONPointer]bool)
	merged := make([]JSONPointer, 0, len(mandatoryPointers)+len(selectivePointers))

	// Add mandatory pointers first
	for _, p := range mandatoryPointers {
		if !seen[p] {
			merged = append(merged, p)
			seen[p] = true
		}
	}

	// Add selective pointers
	for _, p := range selectivePointers {
		if !seen[p] {
			merged = append(merged, p)
			seen[p] = true
		}
	}

	return merged
}
