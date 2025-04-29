package bootstrapper

import (
	"context"
	"fmt"
	"vc/pkg/education"
	"vc/pkg/socialsecurity"
)

type Client struct {
	pid     map[string]pidUsers
	pda1    map[string]socialsecurity.PDA1Document
	ehic    map[string]socialsecurity.EHICDocument
	diploma map[string]education.DiplomaDocument
	elm     map[string]education.ELMDocument

	pda1Client *pda1Client
}

func New(ctx context.Context) (*Client, error) {
	client := &Client{
		pid:     map[string]pidUsers{},
		ehic:    map[string]socialsecurity.EHICDocument{},
		diploma: map[string]education.DiplomaDocument{},
		elm:     map[string]education.ELMDocument{},
	}

	var err error

	client.pda1Client, err = NewPDA1Client(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new pda1 client: %w", err)
	}

	client.MakePID()
	client.MakeEHIC()

	if err := client.bootstrapping(ctx); err != nil {
		return nil, fmt.Errorf("bootstrapping: %w", err)
	}

	return client, nil
}

func (c *Client) bootstrapping(ctx context.Context) error {
	for pidNumber, user := range c.pid {
		if ehic, ok := c.ehic[pidNumber]; ok {
			// upload ehic
			fmt.Println("Uploading EHIC for user:", user.familyName, ehic.SocialSecurityPin)
		}

	}

	return nil
}
