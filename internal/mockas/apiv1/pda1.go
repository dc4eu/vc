package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"vc/pkg/pda1"

	"github.com/brianvoe/gofakeit/v6"
)

// PDA1Service holds the PDA1 document type
type PDA1Service struct {
	Client *Client
}

func (s *PDA1Service) random(ctx context.Context, person *gofakeit.PersonInfo) map[string]any {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	doc := pda1.Document{
		SocialSecurityPin: gofakeit.Numerify("##########"),
		Nationality:       []string{s.Client.randomISO31661Alpha2EU()},
		DetailsOfEmployment: []pda1.DetailsOfEmployment{
			{
				TypeOfEmployment: gofakeit.RandomString([]string{"01", "02"}),
				Name:             gofakeit.Company(),
				Address: pda1.AddressWithCountry{
					Street:   gofakeit.Street(),
					PostCode: gofakeit.Zip(),
					Town:     gofakeit.City(),
					Country:  s.Client.randomISO31661Alpha2EU(),
				},
				IDsOfEmployer: []pda1.IDsOfEmployer{
					{
						EmployerID: gofakeit.UUID(),
						TypeOfID:   gofakeit.RandomString([]string{"01", "02", "03", "98"}),
					},
				},
			},
		},
		PlacesOfWork: []pda1.PlacesOfWork{
			{
				NoFixedPlaceOfWorkExist: false,
				CountryWork:             s.Client.randomISO31661Alpha2EU(),
				PlaceOfWork: []pda1.PlaceOfWork{
					{
						CompanyVesselName: gofakeit.Company(),
						FlagStateHomeBase: gofakeit.Country(),
						IDsOfCompany: []pda1.IDsOfCompany{
							{
								CompanyID: gofakeit.UUID(),
								TypeOfID:  gofakeit.RandomString([]string{"01", "02", "03", "98"}),
							},
						},
						Address: pda1.Address{
							Street:   gofakeit.Street(),
							PostCode: gofakeit.Zip(),
							Town:     gofakeit.City(),
						},
					},
				},
			},
		},
		DecisionLegislationApplicable: pda1.DecisionLegislationApplicable{
			MemberStateWhichLegislationApplies: s.Client.randomISO31661Alpha2EU(),
			TransitionalRuleApply:              false,
			StartingDate:                       "1970-01-01",
			EndingDate:                         "2038-01-19",
		},
		StatusConfirmation:           "01",
		UniqueNumberOfIssuedDocument: "asd123",
		CompetentInstitution: pda1.CompetentInstitution{
			InstitutionID:   fmt.Sprintf("%s:%s", s.Client.randomISO31661Alpha2EU(), gofakeit.Numerify("####")),
			InstitutionName: gofakeit.Company(),
			CountryCode:     s.Client.randomISO31661Alpha2EU(),
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
