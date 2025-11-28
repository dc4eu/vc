//go:build vc20

package ecdsasd

import (
	"encoding/json"
	"testing"
)

func TestApplyJSONPointer(t *testing.T) {
	doc := map[string]interface{}{
		"foo":  []interface{}{"bar", "baz"},
		"":     0,
		"a/b":  1,
		"c%d":  2,
		"e^f":  3,
		"g|h":  4,
		"i\\j": 5,
		"k\"l": 6,
		" ":    7,
		"m~n":  8,
	}

	tests := []struct {
		name    string
		pointer JSONPointer
		want    interface{}
		wantErr bool
	}{
		{
			name:    "whole document",
			pointer: "",
			want:    doc,
			wantErr: false,
		},
		{
			name:    "array element",
			pointer: "/foo/0",
			want:    "bar",
			wantErr: false,
		},
		{
			name:    "array element 2",
			pointer: "/foo/1",
			want:    "baz",
			wantErr: false,
		},
		{
			name:    "empty string key",
			pointer: "/",
			want:    0,
			wantErr: false,
		},
		{
			name:    "key with slash",
			pointer: "/a~1b",
			want:    1,
			wantErr: false,
		},
		{
			name:    "key with percent",
			pointer: "/c%d",
			want:    2,
			wantErr: false,
		},
		{
			name:    "key with caret",
			pointer: "/e^f",
			want:    3,
			wantErr: false,
		},
		{
			name:    "key with pipe",
			pointer: "/g|h",
			want:    4,
			wantErr: false,
		},
		{
			name:    "key with backslash",
			pointer: "/i\\j",
			want:    5,
			wantErr: false,
		},
		{
			name:    "key with quote",
			pointer: "/k\"l",
			want:    6,
			wantErr: false,
		},
		{
			name:    "key with space",
			pointer: "/ ",
			want:    7,
			wantErr: false,
		},
		{
			name:    "key with tilde",
			pointer: "/m~0n",
			want:    8,
			wantErr: false,
		},
		{
			name:    "nonexistent key",
			pointer: "/nonexistent",
			wantErr: true,
		},
		{
			name:    "array index out of bounds",
			pointer: "/foo/99",
			wantErr: true,
		},
		{
			name:    "invalid array index",
			pointer: "/foo/abc",
			wantErr: true,
		},
		{
			name:    "missing leading slash",
			pointer: "foo",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ApplyJSONPointer(doc, tt.pointer)
			if (err != nil) != tt.wantErr {
				t.Errorf("ApplyJSONPointer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !deepEqual(got, tt.want) {
				t.Errorf("ApplyJSONPointer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateJSONPointer(t *testing.T) {
	tests := []struct {
		name    string
		pointer JSONPointer
		wantErr bool
	}{
		{
			name:    "empty pointer",
			pointer: "",
			wantErr: false,
		},
		{
			name:    "root pointer",
			pointer: "/",
			wantErr: false,
		},
		{
			name:    "simple pointer",
			pointer: "/foo/bar",
			wantErr: false,
		},
		{
			name:    "pointer with escaped slash",
			pointer: "/a~1b",
			wantErr: false,
		},
		{
			name:    "pointer with escaped tilde",
			pointer: "/m~0n",
			wantErr: false,
		},
		{
			name:    "missing leading slash",
			pointer: "foo",
			wantErr: true,
		},
		{
			name:    "invalid escape sequence",
			pointer: "/foo~2bar",
			wantErr: true,
		},
		{
			name:    "incomplete escape sequence",
			pointer: "/foo~",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJSONPointer(tt.pointer)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJSONPointer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSelectFields(t *testing.T) {
	docJSON := `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {
			"id": "did:example:subject",
			"name": "John Doe",
			"age": 30
		}
	}`

	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(docJSON), &doc); err != nil {
		t.Fatalf("failed to parse test document: %v", err)
	}

	tests := []struct {
		name     string
		pointers []JSONPointer
		wantKeys []string // Keys that should exist in result
		wantErr  bool
	}{
		{
			name: "select issuer",
			pointers: []JSONPointer{
				"/issuer",
			},
			wantKeys: []string{"issuer"},
			wantErr:  false,
		},
		{
			name: "select nested field",
			pointers: []JSONPointer{
				"/credentialSubject/name",
			},
			wantKeys: []string{"credentialSubject"},
			wantErr:  false,
		},
		{
			name: "select multiple fields",
			pointers: []JSONPointer{
				"/issuer",
				"/credentialSubject/id",
				"/credentialSubject/name",
			},
			wantKeys: []string{"issuer", "credentialSubject"},
			wantErr:  false,
		},
		{
			name:     "no pointers",
			pointers: []JSONPointer{},
			wantErr:  true,
		},
		{
			name: "invalid pointer",
			pointers: []JSONPointer{
				"/nonexistent",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SelectFields(doc, tt.pointers)
			if (err != nil) != tt.wantErr {
				t.Errorf("SelectFields() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				resultMap, ok := result.(map[string]interface{})
				if !ok {
					t.Errorf("SelectFields() result is not a map")
					return
				}

				for _, key := range tt.wantKeys {
					if _, ok := resultMap[key]; !ok {
						t.Errorf("SelectFields() result missing key '%s'", key)
					}
				}
			}
		})
	}
}

func TestIsMandatory(t *testing.T) {
	mandatoryPointers := []JSONPointer{
		"/issuer",
		"/credentialSubject/id",
		"/@context",
	}

	tests := []struct {
		name     string
		pointer  JSONPointer
		expected bool
	}{
		{
			name:     "is mandatory",
			pointer:  "/issuer",
			expected: true,
		},
		{
			name:     "is mandatory nested",
			pointer:  "/credentialSubject/id",
			expected: true,
		},
		{
			name:     "is not mandatory",
			pointer:  "/credentialSubject/name",
			expected: false,
		},
		{
			name:     "empty pointer",
			pointer:  "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsMandatory(tt.pointer, mandatoryPointers)
			if got != tt.expected {
				t.Errorf("IsMandatory() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFilterPointers(t *testing.T) {
	mandatoryPointers := []JSONPointer{
		"/issuer",
		"/credentialSubject/id",
	}

	allPointers := []JSONPointer{
		"/issuer",
		"/credentialSubject/id",
		"/credentialSubject/name",
		"/credentialSubject/age",
	}

	filtered := FilterPointers(allPointers, mandatoryPointers)

	// Should have 2 pointers (name and age)
	if len(filtered) != 2 {
		t.Errorf("FilterPointers() returned %d pointers, expected 2", len(filtered))
	}

	// Verify mandatory pointers are not in filtered list
	for _, fp := range filtered {
		if IsMandatory(fp, mandatoryPointers) {
			t.Errorf("FilterPointers() included mandatory pointer: %s", fp)
		}
	}
}

func TestMergePointers(t *testing.T) {
	mandatoryPointers := []JSONPointer{
		"/issuer",
		"/credentialSubject/id",
	}

	selectivePointers := []JSONPointer{
		"/credentialSubject/name",
		"/credentialSubject/id", // Duplicate
		"/credentialSubject/age",
	}

	merged := MergePointers(mandatoryPointers, selectivePointers)

	// Should have 4 unique pointers
	if len(merged) != 4 {
		t.Errorf("MergePointers() returned %d pointers, expected 4", len(merged))
	}

	// Check for duplicates
	seen := make(map[JSONPointer]bool)
	for _, p := range merged {
		if seen[p] {
			t.Errorf("MergePointers() contains duplicate: %s", p)
		}
		seen[p] = true
	}

	// Mandatory pointers should come first
	if merged[0] != "/issuer" {
		t.Errorf("MergePointers() first pointer = %s, want /issuer", merged[0])
	}
}

func TestEscapeUnescapeJSONPointerToken(t *testing.T) {
	tests := []struct {
		name     string
		original string
		escaped  string
	}{
		{
			name:     "slash",
			original: "a/b",
			escaped:  "a~1b",
		},
		{
			name:     "tilde",
			original: "m~n",
			escaped:  "m~0n",
		},
		{
			name:     "both",
			original: "a/b~c",
			escaped:  "a~1b~0c",
		},
		{
			name:     "none",
			original: "abc",
			escaped:  "abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test escape
			escaped := escapeJSONPointerToken(tt.original)
			if escaped != tt.escaped {
				t.Errorf("escapeJSONPointerToken(%q) = %q, want %q", tt.original, escaped, tt.escaped)
			}

			// Test unescape
			unescaped := unescapeJSONPointerToken(tt.escaped)
			if unescaped != tt.original {
				t.Errorf("unescapeJSONPointerToken(%q) = %q, want %q", tt.escaped, unescaped, tt.original)
			}
		})
	}
}

func TestSetValueAtPointer(t *testing.T) {
	tests := []struct {
		name    string
		pointer JSONPointer
		value   interface{}
		wantErr bool
	}{
		{
			name:    "simple key",
			pointer: "/foo",
			value:   "bar",
			wantErr: false,
		},
		{
			name:    "nested key",
			pointer: "/foo/bar/baz",
			value:   123,
			wantErr: false,
		},
		{
			name:    "empty pointer",
			pointer: "",
			wantErr: true,
		},
		{
			name:    "missing leading slash",
			pointer: "foo",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := make(map[string]interface{})
			err := setValueAtPointer(target, tt.pointer, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("setValueAtPointer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify value was set
				retrieved, err := ApplyJSONPointer(target, tt.pointer)
				if err != nil {
					t.Errorf("failed to retrieve set value: %v", err)
					return
				}
				if !deepEqual(retrieved, tt.value) {
					t.Errorf("retrieved value = %v, want %v", retrieved, tt.value)
				}
			}
		})
	}
}

// deepEqual is a helper to compare interface{} values
func deepEqual(a, b interface{}) bool {
	aJSON, _ := json.Marshal(a)
	bJSON, _ := json.Marshal(b)
	return string(aJSON) == string(bJSON)
}
