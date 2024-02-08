package apiv1

import (
	"context"
	"vc/pkg/ehic"
	"vc/pkg/eidas"

	"github.com/brianvoe/gofakeit/v6"
)

// EHICService holds the EHIC document type
type EHICService struct {
	Client *Client
}

func (s *EHICService) random(ctx context.Context) any {
	doc := ehic.Document{
		PID: eidas.Identification{
			FirstName:   gofakeit.FirstName(),
			LastName:    gofakeit.LastName(),
			Gender:      gofakeit.Gender(),
			PINS:        []string{},
			ExhibitorID: gofakeit.Numerify("##########"),
		},
		CardHolder: ehic.CardHolder{
			FamilyName:       gofakeit.LastName(),
			GivenName:        gofakeit.FirstName(),
			BirthDate:        gofakeit.Date().String(),
			ID:               gofakeit.UUID(),
			CardholderStatus: "",
		},
		CompetentInstitution: ehic.CompetentInstitution{},
		CardInformation:      ehic.CardInformation{},
		Signature:            ehic.Signature{},
	}

	return doc
}
