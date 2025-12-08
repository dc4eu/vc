package oauth2

import (
	"errors"
	"net/url"
	"reflect"
	"slices"
)

type Client struct {
	Type        string   `json:"type" yaml:"type" validate:"required"`
	RedirectURI string   `json:"redirect_uri" yaml:"redirect_uri" validate:"required"`
	Scopes      []string `json:"scopes" yaml:"scopes" validate:"required"`
}

type Clients map[string]*Client

func (c *Clients) Allow(clientID, redirectURI, scope string) (bool, error) {
	client, ok := (*c)[clientID]
	if !ok {
		return false, errors.New("client not found in config")
	}

	urlFromWallet, err := url.Parse(redirectURI)
	if err != nil {
		return false, err
	}
	urlFromConfig, err := url.Parse(client.RedirectURI)
	if err != nil {
		return false, err
	}

	if !reflect.DeepEqual(urlFromWallet, urlFromConfig) {
		return false, errors.New("redirect_url do not match")
	}

	if !slices.Contains(client.Scopes, scope) {
		return false, errors.New("requested scope is not allowed for this client")
	}

	return true, nil
}
