package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var mockClients = Clients{
	"client_1": {
		Type:        "public",
		RedirectURI: "https://example.com/callback",
		Scopes:      []string{"ehic", "diploma"},
	},
	"client_2": {
		Type:        "restricted",
		RedirectURI: "https://example.com/callback",
		Scopes:      []string{"diploma", "elm"},
	},
}

func TestAllow(t *testing.T) {
	tts := []struct {
		name        string
		clientID    string
		redirectURI string
		scope       string
		clients     Clients
		want        bool
	}{
		{
			name:        "valid client",
			clientID:    "client_1",
			redirectURI: "https://example.com/callback",
			scope:       "ehic",
			clients:     mockClients,
			want:        true,
		},
		{
			name:        "invalid client",
			clientID:    "client_2",
			redirectURI: "https://example.com/callback",
			scope:       "el",
			clients:     mockClients,
			want:        false,
		},
		{
			name:        "invalid client",
			clientID:    "client_not_in_dataset",
			redirectURI: "https://example.com/callback",
			scope:       "openid",
			clients:     mockClients,
			want:        false,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.clients.Allow(tt.clientID, tt.redirectURI, tt.scope)
			assert.Equal(t, tt.want, got)
		})
	}
}
