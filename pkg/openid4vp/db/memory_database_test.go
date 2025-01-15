package db

import (
	"testing"
)

func TestInMemoryRepo_flows(t *testing.T) {
	err := Exemple_usage()
	if err != nil {
		t.Fatal(err)
	}
}
