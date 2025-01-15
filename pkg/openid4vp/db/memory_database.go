package db

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"sync"
)

type Entry[T any] struct {
	ID   string
	Data T
}

var (
	ErrIDExists   = errors.New("entry with given ID already exists")
	ErrIDNotFound = errors.New("entry with given ID not found")
)

type Repository[T any] interface {
	Create(entry *Entry[T]) (*Entry[T], error)
	Read(id string) (*Entry[T], bool)
	ReadAll() []*Entry[T]
	Delete(id string) bool
}

const maxEntries = 100

// InMemoryRepo to be used during dev. until api including endpoints are more stable/fixed
type InMemoryRepo[T any] struct {
	mu      sync.Mutex
	entries []*Entry[T]
	index   map[string]int // ID -> position i slice
}

func NewInMemoryRepo[T any]() *InMemoryRepo[T] {
	return &InMemoryRepo[T]{
		entries: make([]*Entry[T], 0, maxEntries),
		index:   make(map[string]int),
	}
}

func (r *InMemoryRepo[T]) Create(entry *Entry[T]) (*Entry[T], error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}

	if _, exists := r.index[entry.ID]; exists {
		return nil, ErrIDExists
	}

	if len(r.entries) >= maxEntries {
		oldestID := r.entries[0].ID
		r.entries = r.entries[1:]
		delete(r.index, oldestID)
	}

	r.entries = append(r.entries, entry)
	r.index[entry.ID] = len(r.entries) - 1

	return entry, nil
}

func (r *InMemoryRepo[T]) Read(id string) (*Entry[T], bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	pos, exists := r.index[id]
	if !exists {
		return nil, false
	}
	return r.entries[pos], true
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

	r.entries = make([]*Entry[T], 0, maxEntries)
	r.index = make(map[string]int)
}

type ExempleStruct struct {
	Name  string
	Email string
}

func Exemple_usage() error {
	repo := NewInMemoryRepo[ExempleStruct]()

	u1, err := repo.Create(&Entry[ExempleStruct]{Data: ExempleStruct{Name: "Alice", Email: "alice@example.com"}})
	if err != nil {
		return err
	}

	u1.Data.Email = "alice@newdomain.com"

	fmt.Println(repo.Read(u1.ID))

	err = addAnother("Benny", "bennylennykenny@example.com", repo)
	if err != nil {
		return err
	}

	for _, user := range repo.ReadAll() {
		fmt.Println(*user)
	}

	repo.Delete(u1.ID)

	for _, user := range repo.ReadAll() {
		fmt.Println(*user)
	}

	repo.Clear()

	for _, user := range repo.ReadAll() {
		fmt.Println(*user)
	}

	return nil
}

func addAnother(name string, email string, repository Repository[ExempleStruct]) error {
	_, err := repository.Create(&Entry[ExempleStruct]{
		ID: uuid.New().String(),
		Data: ExempleStruct{
			Name: name, Email: email,
		},
	})
	if err != nil {
		return err
	}
	return nil
}
