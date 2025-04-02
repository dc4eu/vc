package db

import (
	"errors"
	"github.com/google/uuid"
	"sync"
)

type Entry[T any] struct {
	ID   string
	Data *T
}

var (
	ErrIDExists = errors.New("entry with given ID already exists")
)

type Repository[T any] interface {
	Create(entry *Entry[T]) (*Entry[T], error)
	Read(id string) *Entry[T]
	ReadAll() []*Entry[T]
	Delete(id string) bool
	Clear()
}

// InMemoryRepo to be used during dev. until api including endpoints are more stable/fixed (use: mongodb in production, and with TTL-index for stored sessions)
type InMemoryRepo[T any] struct {
	mu         sync.Mutex
	entries    []*Entry[T]
	index      map[string]int // ID -> position i slice
	maxEntries int
}

func NewInMemoryRepo[T any](maxEntries int) *InMemoryRepo[T] {
	return &InMemoryRepo[T]{
		entries:    make([]*Entry[T], 0, maxEntries),
		index:      make(map[string]int),
		maxEntries: maxEntries,
	}
}

func (r *InMemoryRepo[T]) Create(entry *Entry[T]) (*Entry[T], error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}

	if _, exists := r.index[entry.ID]; exists {
		return nil, ErrIDExists
	}

	if len(r.entries) >= r.maxEntries {
		oldestID := r.entries[0].ID
		r.entries = r.entries[1:]
		delete(r.index, oldestID)
	}

	r.entries = append(r.entries, entry)
	r.index[entry.ID] = len(r.entries) - 1

	return entry, nil
}

func (r *InMemoryRepo[T]) Read(id string) *Entry[T] {
	r.mu.Lock()
	defer r.mu.Unlock()

	pos, exists := r.index[id]
	if !exists {
		return nil
	}
	return r.entries[pos]
}

func (r *InMemoryRepo[T]) ReadAll() []*Entry[T] {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := make([]*Entry[T], len(r.entries))
	copy(result, r.entries)
	return result
}

func (r *InMemoryRepo[T]) Delete(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	pos, exists := r.index[id]
	if !exists {
		return false
	}

	delete(r.index, id)

	lastIdx := len(r.entries) - 1
	if pos != lastIdx {
		r.entries[pos] = r.entries[lastIdx]
		r.index[r.entries[pos].ID] = pos
	}
	r.entries = r.entries[:lastIdx]

	return true
}

func (r *InMemoryRepo[T]) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.entries = make([]*Entry[T], 0, r.maxEntries)
	r.index = make(map[string]int)
}
