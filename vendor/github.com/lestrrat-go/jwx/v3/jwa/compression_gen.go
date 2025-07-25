// Code generated by tools/cmd/genjwa/main.go. DO NOT EDIT.

package jwa

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

var muAllCompressionAlgorithm sync.RWMutex
var allCompressionAlgorithm = map[string]CompressionAlgorithm{}
var muListCompressionAlgorithm sync.RWMutex
var listCompressionAlgorithm []CompressionAlgorithm
var builtinCompressionAlgorithm = map[string]struct{}{}

func init() {
	// builtin values for CompressionAlgorithm
	algorithms := make([]CompressionAlgorithm, 2)
	algorithms[0] = NewCompressionAlgorithm("DEF")
	algorithms[1] = NewCompressionAlgorithm("")

	RegisterCompressionAlgorithm(algorithms...)
}

// Deflate returns an object representing the "DEF" content compression algorithm value. Using this value specifies that the content should be compressed using DEFLATE (RFC 1951).
func Deflate() CompressionAlgorithm {
	return lookupBuiltinCompressionAlgorithm("DEF")
}

// NoCompress returns an object representing an empty compression algorithm value. Using this value specifies that the content should not be compressed.
func NoCompress() CompressionAlgorithm {
	return lookupBuiltinCompressionAlgorithm("")
}

func lookupBuiltinCompressionAlgorithm(name string) CompressionAlgorithm {
	muAllCompressionAlgorithm.RLock()
	v, ok := allCompressionAlgorithm[name]
	muAllCompressionAlgorithm.RUnlock()
	if !ok {
		panic(fmt.Sprintf(`jwa: CompressionAlgorithm %q not registered`, name))
	}
	return v
}

// CompressionAlgorithm represents the compression algorithms as described in https://tools.ietf.org/html/rfc7518#section-7.3
type CompressionAlgorithm struct {
	name       string
	deprecated bool
}

func (s CompressionAlgorithm) String() string {
	return s.name
}

// IsDeprecated returns true if the CompressionAlgorithm object is deprecated.
func (s CompressionAlgorithm) IsDeprecated() bool {
	return s.deprecated
}

// EmptyCompressionAlgorithm returns an empty CompressionAlgorithm object, used as a zero value.
func EmptyCompressionAlgorithm() CompressionAlgorithm {
	return CompressionAlgorithm{}
}

// NewCompressionAlgorithm creates a new CompressionAlgorithm object with the given name.
func NewCompressionAlgorithm(name string, options ...NewAlgorithmOption) CompressionAlgorithm {
	var deprecated bool
	for _, option := range options {
		switch option.Ident() {
		case identDeprecated{}:
			if err := option.Value(&deprecated); err != nil {
				panic("jwa.NewCompressionAlgorithm: WithDeprecated option must be a boolean")
			}
		}
	}
	return CompressionAlgorithm{name: name, deprecated: deprecated}
}

// LookupCompressionAlgorithm returns the CompressionAlgorithm object for the given name.
func LookupCompressionAlgorithm(name string) (CompressionAlgorithm, bool) {
	muAllCompressionAlgorithm.RLock()
	v, ok := allCompressionAlgorithm[name]
	muAllCompressionAlgorithm.RUnlock()
	return v, ok
}

// RegisterCompressionAlgorithm registers a new CompressionAlgorithm. The signature value must be immutable
// and safe to be used by multiple goroutines, as it is going to be shared with all other users of this library.
func RegisterCompressionAlgorithm(algorithms ...CompressionAlgorithm) {
	muAllCompressionAlgorithm.Lock()
	for _, alg := range algorithms {
		allCompressionAlgorithm[alg.String()] = alg
	}
	muAllCompressionAlgorithm.Unlock()
	rebuildCompressionAlgorithm()
}

// UnregisterCompressionAlgorithm unregisters a CompressionAlgorithm from its known database.
// Non-existent entries, as well as built-in algorithms will silently be ignored.
func UnregisterCompressionAlgorithm(algorithms ...CompressionAlgorithm) {
	muAllCompressionAlgorithm.Lock()
	for _, alg := range algorithms {
		if _, ok := builtinCompressionAlgorithm[alg.String()]; ok {
			continue
		}
		delete(allCompressionAlgorithm, alg.String())
	}
	muAllCompressionAlgorithm.Unlock()
	rebuildCompressionAlgorithm()
}

func rebuildCompressionAlgorithm() {
	list := make([]CompressionAlgorithm, 0, len(allCompressionAlgorithm))
	muAllCompressionAlgorithm.RLock()
	for _, v := range allCompressionAlgorithm {
		list = append(list, v)
	}
	muAllCompressionAlgorithm.RUnlock()
	sort.Slice(list, func(i, j int) bool {
		return list[i].String() < list[j].String()
	})
	muListCompressionAlgorithm.Lock()
	listCompressionAlgorithm = list
	muListCompressionAlgorithm.Unlock()
}

// CompressionAlgorithms returns a list of all available values for CompressionAlgorithm.
func CompressionAlgorithms() []CompressionAlgorithm {
	muListCompressionAlgorithm.RLock()
	defer muListCompressionAlgorithm.RUnlock()
	return listCompressionAlgorithm
}

// MarshalJSON serializes the CompressionAlgorithm object to a JSON string.
func (s CompressionAlgorithm) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON deserializes the JSON string to a CompressionAlgorithm object.
func (s *CompressionAlgorithm) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return fmt.Errorf(`failed to unmarshal CompressionAlgorithm: %w`, err)
	}
	v, ok := LookupCompressionAlgorithm(name)
	if !ok {
		return fmt.Errorf(`unknown CompressionAlgorithm: %q`, name)
	}
	*s = v
	return nil
}
