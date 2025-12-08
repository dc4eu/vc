package oauth2

import (
	"errors"
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
	type want struct {
		allowed bool
		err     error
	}
	tts := []struct {
		name        string
		clientID    string
		redirectURI string
		scope       string
		clients     Clients
		want        want
	}{
		{
			name:        "valid client",
			clientID:    "client_1",
			redirectURI: "https://example.com/callback",
			scope:       "ehic",
			clients:     mockClients,
			want:        want{allowed: true, err: nil},
		},
		{
			name:        "invalid client",
			clientID:    "client_2",
			redirectURI: "https://example.com/callback",
			scope:       "el",
			clients:     mockClients,
			want:        want{allowed: false, err: errors.New("requested scope is not allowed for this client")},
		},
		{
			name:        "client not in config",
			clientID:    "client_not_in_dataset",
			redirectURI: "https://example.com/callback",
			scope:       "openid",
			clients:     mockClients,
			want:        want{allowed: false, err: errors.New("client not found in config")},
		},
		{
			name:        "redirect url trailing slash",
			clientID:    "client_1",
			redirectURI: "https://example.com/callback/",
			scope:       "ehic",
			clients:     mockClients,
			want:        want{allowed: false, err: errors.New("redirect_url do not match")},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.clients.Allow(tt.clientID, tt.redirectURI, tt.scope)
			assert.Equal(t, tt.want.allowed, got)
			assert.Equal(t, tt.want.err, err)
		})
	}
}
