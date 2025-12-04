package common

// HasType checks if a JSON-LD object has a specific type
func HasType(m map[string]any, expectedType string) bool {
	t, ok := m["type"]
	if !ok {
		t, ok = m["@type"]
	}
	if !ok {
		return false
	}

	if s, ok := t.(string); ok {
		return s == expectedType
	}
	if list, ok := t.([]any); ok {
		for _, item := range list {
			if s, ok := item.(string); ok && s == expectedType {
				return true
			}
		}
	}
	return false
}

// FindProofNode recursively searches for a proof node in a JSON-LD object
func FindProofNode(data any, proofType string) map[string]any {
	if m, ok := data.(map[string]any); ok {
		if HasType(m, proofType) || HasType(m, "Proof") {
			return m
		}
		// Check all values
		for _, v := range m {
			if found := FindProofNode(v, proofType); found != nil {
				return found
			}
		}
	} else if list, ok := data.([]any); ok {
		for _, item := range list {
			if found := FindProofNode(item, proofType); found != nil {
				return found
			}
		}
	}
	return nil
}
