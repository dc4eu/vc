package apiv1

import (
	"context"
	"encoding/json"
	"vc/pkg/ehic"
	"vc/pkg/eidas"

	"github.com/brianvoe/gofakeit/v6"
)

// EHICService holds the EHIC document type
type EHICService struct {
	Client *Client
}

func (s *EHICService) random(ctx context.Context, person *gofakeit.PersonInfo) map[string]any {
	doc := ehic.Document{
		PID: eidas.Identification{
			FirstName:   person.FirstName,
			LastName:    person.LastName,
			Gender:      person.Gender,
			PINS:        []string{},
			ExhibitorID: gofakeit.Numerify("##########"),
		},
		CardHolder: ehic.CardHolder{
			FamilyName:       person.LastName,
			GivenName:        person.FirstName,
			BirthDate:        gofakeit.Date().String(),
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

	d, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}

	var t map[string]any
	if err := json.Unmarshal(d, &t); err != nil {
		panic(err)
	}

	return t
}
