package openid4vp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExamplePresentationDefinition(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "example-presentation-definition"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ExamplePresentationDefinition()
			assert.NoError(t, err)
		})
	}
}

func TestExamplePresentationSubmission(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "example-presentation-submission"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ExamplePresentationSubmission()
		})
	}
}
