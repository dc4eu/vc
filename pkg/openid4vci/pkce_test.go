package openid4vci

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateCodeVerifier(t *testing.T) {
	tests := []struct {
		name         string
		wantedLength int
	}{
		{
			name:         "OK",
			wantedLength: 43,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CreateCodeVerifier()

			assert.GreaterOrEqual(t, len(got), 43)
		})
	}
}

func TestCreateCodeChallenge(t *testing.T) {
	tests := []struct {
		name                string
		codeChallengeMethod string
		codeVerifier        string
	}{
		{
			name:                "OK",
			codeChallengeMethod: CodeChallengeMethodS256,
			codeVerifier:        "test_code",
		},
		{
			name:                "OK",
			codeChallengeMethod: CodeChallengeMethodPlain,
			codeVerifier:        "test_code",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CreateCodeChallenge(tt.codeChallengeMethod, tt.codeVerifier)
			fmt.Println("got: ", got)
			assert.NotEmpty(t, got)
		})
	}
}

