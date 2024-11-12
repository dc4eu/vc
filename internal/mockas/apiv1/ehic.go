package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"vc/pkg/ehic"

	"github.com/brianvoe/gofakeit/v6"
)

// EHICService holds the EHIC document type
type EHICService struct {
	Client *Client
}

func (s *EHICService) random(ctx context.Context, person *gofakeit.PersonInfo) map[string]any {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	doc := ehic.Document{
		Subject: ehic.Subject{
			Forename:    person.FirstName,
			FamilyName:  person.LastName,
			DateOfBirth: gofakeit.Date().String(),
			OtherElements: ehic.OtherElements{
				Sex:               gofakeit.RandomString([]string{"01", "02", "98"}),
				ForenameAtBirth:   person.FirstName,
				FamilyNameAtBirth: person.LastName,
			},
		},
		SocialSecurityPin: gofakeit.Numerify("##########"),
		PeriodEntitlement: ehic.PeriodEntitlement{
			StartingDate: gofakeit.Date().String(),
			EndingDate:   gofakeit.Date().String(),
		},
		DocumentID: gofakeit.UUID(),
		CompetentInstitution: ehic.CompetentInstitution{
			InstitutionID:      fmt.Sprintf("%s:%s", gofakeit.RandomString([]string{"SE", "DK", "NO", "FI"}), gofakeit.Numerify("####")),
			InstitutionName:    gofakeit.Company(),
			InstitutionCountry: gofakeit.RandomString([]string{"SE", "DK", "NO", "FI"}),
		},
	}

	jsonBytes, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}

	reply := map[string]any{}
	if err := json.Unmarshal(jsonBytes, &reply); err != nil {
		panic(err)
	}

	return reply
}
