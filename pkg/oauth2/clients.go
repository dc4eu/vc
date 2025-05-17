package oauth2

import (
	"fmt"
	"slices"
)

type Client struct {
	Type        string   `json:"type" yaml:"type" validate:"required"`
	RedirectURI string   `json:"redirect_uri" yaml:"redirect_uri" validate:"required"`
	Scopes      []string `json:"scopes" yaml:"scopes" validate:"required"`
}

type Clients map[string]*Client

func (c *Clients) Allow(clientID, redirectURI, scope string) bool {
	client, ok := (*c)[clientID]
	if !ok {
		fmt.Println("client not found")
		return false
	}

	if client.RedirectURI != redirectURI {
		fmt.Println("redirect uri not match")
		return false
	}

	if !slices.Contains(client.Scopes, scope) {
		return false
	}

	return true
}
