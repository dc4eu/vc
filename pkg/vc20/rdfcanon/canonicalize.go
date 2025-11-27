//go:build vc20

package rdfcanon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/piprate/json-gold/ld"
)

// Canonicalizer performs RDF Dataset Canonicalization (RDFC-1.0)
// See: https://www.w3.org/TR/rdf-canon/
type Canonicalizer struct {
	options *ld.JsonLdOptions
}

// NewCanonicalizer creates a new RDF canonicalizer
func NewCanonicalizer() *Canonicalizer {
	opts := ld.NewJsonLdOptions("")
	opts.Algorithm = "URDNA2015" // RDF Dataset Normalization algorithm
	opts.Format = "application/n-quads"

	return &Canonicalizer{
		options: opts,
	}
}

// Canonicalize converts a JSON-LD document to canonical N-Quads format
// This implements the RDFC-1.0 (URDNA2015) algorithm
func (c *Canonicalizer) Canonicalize(doc interface{}) (string, error) {
	proc := ld.NewJsonLdProcessor()

	// Convert JSON-LD to RDF dataset (N-Quads)
	normalized, err := proc.Normalize(doc, c.options)
	if err != nil {
		return "", fmt.Errorf("normalization failed: %w", err)
	}

	// The normalized output is already in canonical form
	normalizedStr, ok := normalized.(string)
	if !ok {
		return "", fmt.Errorf("unexpected normalized format: %T", normalized)
	}

	return normalizedStr, nil
}

// CanonicalizeToDataset converts a JSON-LD document to a canonical RDF dataset
func (c *Canonicalizer) CanonicalizeToDataset(doc interface{}) (*Dataset, error) {
	canonical, err := c.Canonicalize(doc)
	if err != nil {
		return nil, err
	}

	return ParseNQuads(canonical)
}

// Hash computes the SHA-256 hash of a canonicalized document
func (c *Canonicalizer) Hash(doc interface{}) (string, error) {
	canonical, err := c.Canonicalize(doc)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(hash[:]), nil
}

// HashWithAlgorithm computes a hash using the specified algorithm
func (c *Canonicalizer) HashWithAlgorithm(doc interface{}, algorithm string) (string, error) {
	canonical, err := c.Canonicalize(doc)
	if err != nil {
		return "", err
	}

	switch algorithm {
	case "sha256", "SHA-256":
		hash := sha256.Sum256([]byte(canonical))
		return hex.EncodeToString(hash[:]), nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

// Dataset represents an RDF dataset in canonical form
type Dataset struct {
	Quads []Quad
}

// Quad represents a single RDF quad (subject, predicate, object, graph)
type Quad struct {
	Subject   string
	Predicate string
	Object    string
	Graph     string // Optional, empty for default graph
}

// ParseNQuads parses N-Quads format into a Dataset
func ParseNQuads(nquads string) (*Dataset, error) {
	lines := strings.Split(strings.TrimSpace(nquads), "\n")
	quads := make([]Quad, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		quad, err := parseQuad(line)
		if err != nil {
			return nil, fmt.Errorf("failed to parse quad: %w", err)
		}
		quads = append(quads, quad)
	}

	return &Dataset{Quads: quads}, nil
}

// parseQuad parses a single N-Quad line
func parseQuad(line string) (Quad, error) {
	// Remove trailing dot
	line = strings.TrimSuffix(strings.TrimSpace(line), ".")
	line = strings.TrimSpace(line)

	parts := splitQuad(line)
	if len(parts) < 3 {
		return Quad{}, fmt.Errorf("invalid quad format: %s", line)
	}

	quad := Quad{
		Subject:   parts[0],
		Predicate: parts[1],
		Object:    parts[2],
	}

	if len(parts) >= 4 {
		quad.Graph = parts[3]
	}

	return quad, nil
}

// splitQuad splits an N-Quad line into components
// This is a simplified parser that handles basic cases
func splitQuad(line string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	escaped := false

	for i, ch := range line {
		if escaped {
			current.WriteRune(ch)
			escaped = false
			continue
		}

		if ch == '\\' {
			escaped = true
			current.WriteRune(ch)
			continue
		}

		if ch == '"' {
			inQuotes = !inQuotes
			current.WriteRune(ch)
			continue
		}

		if !inQuotes && ch == ' ' {
			// Check if this is a separator between components
			part := strings.TrimSpace(current.String())
			if part != "" {
				parts = append(parts, part)
				current.Reset()
			}
			continue
		}

		current.WriteRune(ch)

		// Special handling for the end
		if i == len(line)-1 {
			part := strings.TrimSpace(current.String())
			if part != "" {
				parts = append(parts, part)
			}
		}
	}

	// Add final part if not already added
	if current.Len() > 0 {
		part := strings.TrimSpace(current.String())
		if part != "" {
			parts = append(parts, part)
		}
	}

	return parts
}

// ToNQuads converts the dataset back to N-Quads format
func (d *Dataset) ToNQuads() string {
	var builder strings.Builder

	for i, quad := range d.Quads {
		builder.WriteString(quad.Subject)
		builder.WriteString(" ")
		builder.WriteString(quad.Predicate)
		builder.WriteString(" ")
		builder.WriteString(quad.Object)

		if quad.Graph != "" {
			builder.WriteString(" ")
			builder.WriteString(quad.Graph)
		}

		builder.WriteString(" .")

		if i < len(d.Quads)-1 {
			builder.WriteString("\n")
		}
	}

	return builder.String()
}

// Sort sorts the quads in the dataset for canonical ordering
func (d *Dataset) Sort() {
	sort.Slice(d.Quads, func(i, j int) bool {
		if d.Quads[i].Subject != d.Quads[j].Subject {
			return d.Quads[i].Subject < d.Quads[j].Subject
		}
		if d.Quads[i].Predicate != d.Quads[j].Predicate {
			return d.Quads[i].Predicate < d.Quads[j].Predicate
		}
		if d.Quads[i].Object != d.Quads[j].Object {
			return d.Quads[i].Object < d.Quads[j].Object
		}
		return d.Quads[i].Graph < d.Quads[j].Graph
	})
}

// Hash computes the SHA-256 hash of the dataset
func (d *Dataset) Hash() string {
	nquads := d.ToNQuads()
	hash := sha256.Sum256([]byte(nquads))
	return hex.EncodeToString(hash[:])
}

// FilterByGraph returns a new dataset containing only quads from the specified graph
func (d *Dataset) FilterByGraph(graph string) *Dataset {
	filtered := &Dataset{
		Quads: make([]Quad, 0),
	}

	for _, quad := range d.Quads {
		if quad.Graph == graph {
			filtered.Quads = append(filtered.Quads, quad)
		}
	}

	return filtered
}

// GetGraphs returns all unique graph names in the dataset
func (d *Dataset) GetGraphs() []string {
	graphSet := make(map[string]bool)

	for _, quad := range d.Quads {
		if quad.Graph != "" {
			graphSet[quad.Graph] = true
		}
	}

	graphs := make([]string, 0, len(graphSet))
	for graph := range graphSet {
		graphs = append(graphs, graph)
	}
	sort.Strings(graphs)

	return graphs
}
