package apiv1

import (
	"context"
	"vc/pkg/ehic"
	"vc/pkg/eidas"
	"vc/pkg/model"

	"github.com/brianvoe/gofakeit/v6"
)

// EHICService holds the EHIC document type
type EHICService struct {
	Client *Client
}

func (s *EHICService) random(ctx context.Context, meta *model.MetaData) any {
	doc := ehic.Document{
		PID: eidas.Identification{
			FirstName:   gofakeit.FirstName(),
			LastName:    gofakeit.LastName(),
			Gender:      gofakeit.Gender(),
			PINS:        []string{},
			ExhibitorID: gofakeit.Numerify("##########"),
		},
		CardHolder: ehic.CardHolder{
			FamilyName:       meta.LastName,
			GivenName:        meta.FirstName,
			BirthDate:        meta.DateOfBirth,
			ID:               gofakeit.UUID(),
			CardholderStatus: gofakeit.RandomString([]string{"active", "inactive"}),
		},
		CompetentInstitution: ehic.CompetentInstitution{
			InstitutionName: gofakeit.Company(),
			ID:              gofakeit.UUID(),
		},
		CardInformation: ehic.CardInformation{
			ID:           gofakeit.UUID(),
			IssuanceDate: gofakeit.Date().String(),
			ValidSince:   gofakeit.Date().String(),
			ExpiryDate:   gofakeit.Date().String(),
			InvalidSince: gofakeit.Date().String(),
			Signature: ehic.Signature{
				Issuer: gofakeit.Company(),
				Seal:   gofakeit.UUID(),
			},
		},
		Signature: ehic.Signature{
			Issuer: gofakeit.Company(),
			Seal:   gofakeit.UUID(),
		},
	}

	return doc
}
