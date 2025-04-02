package openid4vp

import "testing"

func TestExamplePresentationDefinition(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "example-presentation-definition"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ExamplePresentationDefinition()
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
