package bootstrapper

import (
	"context"
	"vc/pkg/socialsecurity"
)

type pda1Client struct {
	client    *Client
	documents map[string]socialsecurity.PDA1Document
}

func NewPDA1Client(ctx context.Context, client *Client) (*pda1Client, error) {
	c := &pda1Client{
		client: client,
	}

	c.make()

	return c, nil
}

func (c *pda1Client) addStaticAttributes() {
	//meta := model.MetaData{}

}

func (c *pda1Client) make() {
	c.documents = map[string]socialsecurity.PDA1Document{
		"70": {
			SocialSecurityPin:             "23451235",
			Nationality:                   []string{"FR"},
			DetailsOfEmployment:           []socialsecurity.DetailsOfEmployment{},
			PlacesOfWork:                  []socialsecurity.PlacesOfWork{},
			DecisionLegislationApplicable: socialsecurity.DecisionLegislationApplicable{},
			StatusConfirmation:            "",
			UniqueNumberOfIssuedDocument:  "",
			CompetentInstitution:          socialsecurity.PDA1CompetentInstitution{},
		},
	}

}
