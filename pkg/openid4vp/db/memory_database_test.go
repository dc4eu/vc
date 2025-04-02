package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"strconv"
	"testing"
)

type ExempleStruct struct {
	ID    string
	Name  string
	Email string
}

func TestInMemoryRepo_flows(t *testing.T) {
	//var repo Repository[ExempleStruct]
	repo := NewInMemoryRepo[ExempleStruct](5)

	entry1Exp := &Entry[ExempleStruct]{Data: &ExempleStruct{ID: uuid.NewString(), Name: "Alice", Email: "alice@example.com"}}
	entry1, err := repo.Create(entry1Exp)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, entry1Exp, repo.Read(entry1.ID), "")

	entry1.Data.Email = "alice@newdomain.com"

	assert.Equal(t, entry1.Data.Email, repo.Read(entry1.ID).Data.Email, "")

	assert.Len(t, repo.ReadAll(), 1, "One entry expected")

	err = addAnother("2", "Benny", "bennylennykenny@example.com", repo)
	if err != nil {
		t.Error(err)
	}
	err = addAnother("2", "Benny", "bennylennykenny@example.com", repo)
	if err == nil {
		t.Error("error expected for duplicate key")
	}

	assert.Len(t, repo.ReadAll(), 2, "Two entrys expected")

	repo.Delete(entry1.ID)
	assert.Len(t, repo.ReadAll(), 1, "One entry expected")

	repo.Clear()

	assert.Len(t, repo.ReadAll(), 0, "Zero entrys expected")

	for i := 0; i < 1000; i++ {
		_, err := repo.Create(&Entry[ExempleStruct]{ID: strconv.Itoa(i), Data: &ExempleStruct{Name: "Alice", Email: "alice@example.com"}})
		if err != nil {
			t.Error(err)
		}
	}
	assert.Len(t, repo.ReadAll(), 5, "Only 5 entries expected")
	for i := 995; i < 1000; i++ {
		entry := repo.Read(strconv.Itoa(i))
		if entry == nil {
			t.Error("entry 995-999 expected")
		}
	}
}

func addAnother(id string, name string, email string, repository Repository[ExempleStruct]) error {
	_, err := repository.Create(&Entry[ExempleStruct]{
		ID: id,
		Data: &ExempleStruct{
			ID: id, Name: name, Email: email,
		},
	})
	if err != nil {
		return err
	}
	return nil
}
