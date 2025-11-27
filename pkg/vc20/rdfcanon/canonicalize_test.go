//go:build vc20

package rdfcanon

import (
	"strings"
	"testing"
)

func TestCanonicalizer_Canonicalize(t *testing.T) {
	tests := []struct {
		name    string
		doc     interface{}
		wantErr bool
	}{
		{
			name: "simple JSON-LD document",
			doc: map[string]interface{}{
				"@context": "https://www.w3.org/ns/credentials/v2",
				"@type":    "VerifiableCredential",
				"name":     "Test Credential",
			},
			wantErr: false,
		},
		{
			name: "document with credentialSubject",
			doc: map[string]interface{}{
				"@context": []interface{}{
					"https://www.w3.org/ns/credentials/v2",
				},
				"@type":  "VerifiableCredential",
				"issuer": "did:example:issuer",
				"credentialSubject": map[string]interface{}{
					"id":   "did:example:subject",
					"name": "John Doe",
				},
			},
			wantErr: false,
		},
		{
			name: "document with array context",
			doc: map[string]interface{}{
				"@context": []interface{}{
					"https://www.w3.org/ns/credentials/v2",
					map[string]interface{}{
						"ex": "https://example.org/",
					},
				},
				"type":           "VerifiableCredential",
				"ex:customField": "value",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCanonicalizer()
			result, err := c.Canonicalize(tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("Canonicalize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == "" {
				t.Error("Canonicalize() returned empty result")
			}
			if !tt.wantErr {
				// Result should be valid N-Quads format
				lines := strings.Split(strings.TrimSpace(result), "\n")
				for i, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					if !strings.HasSuffix(line, ".") {
						t.Errorf("Line %d does not end with '.': %s", i+1, line)
					}
				}
			}
		})
	}
}

func TestCanonicalizer_Hash(t *testing.T) {
	tests := []struct {
		name    string
		doc     interface{}
		wantErr bool
	}{
		{
			name: "simple document",
			doc: map[string]interface{}{
				"@context": "https://www.w3.org/ns/credentials/v2",
				"name":     "Test",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCanonicalizer()
			hash, err := c.Hash(tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Hash should be 64 hex characters (SHA-256)
				if len(hash) != 64 {
					t.Errorf("Hash() length = %d, want 64", len(hash))
				}
			}
		})
	}
}

func TestCanonicalizer_Deterministic(t *testing.T) {
	// Test that canonicalization is deterministic
	doc := map[string]interface{}{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"issuer":   "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"name": "Alice",
			"age":  30,
		},
	}

	c := NewCanonicalizer()

	result1, err := c.Canonicalize(doc)
	if err != nil {
		t.Fatalf("First canonicalization failed: %v", err)
	}

	result2, err := c.Canonicalize(doc)
	if err != nil {
		t.Fatalf("Second canonicalization failed: %v", err)
	}

	if result1 != result2 {
		t.Error("Canonicalization is not deterministic")
		t.Logf("Result 1:\n%s", result1)
		t.Logf("Result 2:\n%s", result2)
	}
}

func TestCanonicalizer_HashDeterministic(t *testing.T) {
	// Test that hashing is deterministic
	doc := map[string]interface{}{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"name":     "Test",
		"value":    42,
	}

	c := NewCanonicalizer()

	hash1, err := c.Hash(doc)
	if err != nil {
		t.Fatalf("First hash failed: %v", err)
	}

	hash2, err := c.Hash(doc)
	if err != nil {
		t.Fatalf("Second hash failed: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("Hash() is not deterministic: %s != %s", hash1, hash2)
	}
}

func TestParseNQuads(t *testing.T) {
	tests := []struct {
		name      string
		nquads    string
		wantQuads int
		wantErr   bool
	}{
		{
			name:      "single quad",
			nquads:    `<http://example.org/subject> <http://example.org/predicate> "Object" .`,
			wantQuads: 1,
			wantErr:   false,
		},
		{
			name: "multiple quads",
			nquads: `<http://example.org/s1> <http://example.org/p1> "O1" .
<http://example.org/s2> <http://example.org/p2> "O2" .`,
			wantQuads: 2,
			wantErr:   false,
		},
		{
			name:      "empty input",
			nquads:    "",
			wantQuads: 0,
			wantErr:   false,
		},
		{
			name: "with comments",
			nquads: `# This is a comment
<http://example.org/subject> <http://example.org/predicate> "Object" .`,
			wantQuads: 1,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataset, err := ParseNQuads(tt.nquads)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseNQuads() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(dataset.Quads) != tt.wantQuads {
				t.Errorf("ParseNQuads() got %d quads, want %d", len(dataset.Quads), tt.wantQuads)
			}
		})
	}
}

func TestDataset_ToNQuads(t *testing.T) {
	dataset := &Dataset{
		Quads: []Quad{
			{
				Subject:   "<http://example.org/subject>",
				Predicate: "<http://example.org/predicate>",
				Object:    "\"Object\"",
			},
		},
	}

	result := dataset.ToNQuads()
	if !strings.Contains(result, "<http://example.org/subject>") {
		t.Error("ToNQuads() missing subject")
	}
	if !strings.HasSuffix(strings.TrimSpace(result), ".") {
		t.Error("ToNQuads() should end with '.'")
	}
}

func TestDataset_Sort(t *testing.T) {
	dataset := &Dataset{
		Quads: []Quad{
			{Subject: "<http://b>", Predicate: "<http://p>", Object: "\"o\""},
			{Subject: "<http://a>", Predicate: "<http://p>", Object: "\"o\""},
			{Subject: "<http://c>", Predicate: "<http://p>", Object: "\"o\""},
		},
	}

	dataset.Sort()

	if dataset.Quads[0].Subject != "<http://a>" {
		t.Error("Sort() first quad should have subject '<http://a>'")
	}
	if dataset.Quads[2].Subject != "<http://c>" {
		t.Error("Sort() last quad should have subject '<http://c>'")
	}
}

func TestDataset_Hash(t *testing.T) {
	dataset := &Dataset{
		Quads: []Quad{
			{
				Subject:   "<http://example.org/subject>",
				Predicate: "<http://example.org/predicate>",
				Object:    "\"Object\"",
			},
		},
	}

	hash := dataset.Hash()
	if len(hash) != 64 {
		t.Errorf("Hash() length = %d, want 64", len(hash))
	}
}

func TestDataset_FilterByGraph(t *testing.T) {
	dataset := &Dataset{
		Quads: []Quad{
			{Subject: "<http://s1>", Predicate: "<http://p>", Object: "\"o\"", Graph: ""},
			{Subject: "<http://s2>", Predicate: "<http://p>", Object: "\"o\"", Graph: "<http://graph1>"},
			{Subject: "<http://s3>", Predicate: "<http://p>", Object: "\"o\"", Graph: "<http://graph2>"},
		},
	}

	filtered := dataset.FilterByGraph("<http://graph1>")
	if len(filtered.Quads) != 1 {
		t.Errorf("FilterByGraph() got %d quads, want 1", len(filtered.Quads))
	}
	if filtered.Quads[0].Subject != "<http://s2>" {
		t.Error("FilterByGraph() returned wrong quad")
	}
}

func TestDataset_GetGraphs(t *testing.T) {
	dataset := &Dataset{
		Quads: []Quad{
			{Subject: "<http://s1>", Predicate: "<http://p>", Object: "\"o\"", Graph: ""},
			{Subject: "<http://s2>", Predicate: "<http://p>", Object: "\"o\"", Graph: "<http://graph1>"},
			{Subject: "<http://s3>", Predicate: "<http://p>", Object: "\"o\"", Graph: "<http://graph2>"},
			{Subject: "<http://s4>", Predicate: "<http://p>", Object: "\"o\"", Graph: "<http://graph1>"},
		},
	}

	graphs := dataset.GetGraphs()
	if len(graphs) != 2 {
		t.Errorf("GetGraphs() got %d graphs, want 2", len(graphs))
	}
}

func TestCanonicalizer_CanonicalizeToDataset(t *testing.T) {
	doc := map[string]interface{}{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"name":     "Test",
	}

	c := NewCanonicalizer()
	dataset, err := c.CanonicalizeToDataset(doc)
	if err != nil {
		t.Fatalf("CanonicalizeToDataset() error = %v", err)
	}
	if dataset == nil {
		t.Fatal("CanonicalizeToDataset() returned nil dataset")
	}
	if len(dataset.Quads) == 0 {
		t.Error("CanonicalizeToDataset() returned empty dataset")
	}
}
