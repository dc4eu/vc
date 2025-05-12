package apiv1

import (
	"context"
	"fmt"
	"time"
	"vc/pkg/socialsecurity"

	"github.com/brianvoe/gofakeit/v6"
)

// PDA1Service holds the PDA1 document type
type PDA1Service struct {
	Client *Client
}

func (s *PDA1Service) random(ctx context.Context, person *person) (map[string]any, error) {
	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	doc := socialsecurity.PDA1Document{
		SocialSecurityPin: gofakeit.Numerify("##########"),
		Nationality:       []string{s.Client.randomISO31661Alpha2EU()},
		DetailsOfEmployment: []socialsecurity.DetailsOfEmployment{
			{
				TypeOfEmployment: gofakeit.RandomString([]string{"01", "02"}),
				Name:             gofakeit.Company(),
				Address: socialsecurity.AddressWithCountry{
					Street:   gofakeit.Street(),
					PostCode: gofakeit.Zip(),
					Town:     gofakeit.City(),
					Country:  s.Client.randomISO31661Alpha2EU(),
				},
				IDsOfEmployer: []socialsecurity.IDsOfEmployer{
					{
						EmployerID: gofakeit.UUID(),
						TypeOfID:   gofakeit.RandomString([]string{"01", "02", "03", "98"}),
					},
				},
			},
		},
		PlacesOfWork: []socialsecurity.PlacesOfWork{
			{
				AFixedPlaceOfWorkExist: false,
				CountryWork:            s.Client.randomISO31661Alpha2EU(),
				PlaceOfWork: []socialsecurity.PlaceOfWork{
					{
						CompanyVesselName: gofakeit.Company(),
						FlagStateHomeBase: gofakeit.Country(),
						IDsOfCompany: []socialsecurity.IDsOfCompany{
							{
								CompanyID: gofakeit.UUID(),
								TypeOfID:  gofakeit.RandomString([]string{"01", "02", "03", "98"}),
							},
						},
						Address: socialsecurity.Address{
							Street:   gofakeit.Street(),
							PostCode: gofakeit.Zip(),
							Town:     gofakeit.City(),
						},
					},
				},
			},
		},
		DecisionLegislationApplicable: socialsecurity.DecisionLegislationApplicable{
			MemberStateWhichLegislationApplies: s.Client.randomISO31661Alpha2EU(),
			TransitionalRuleApply:              false,
			StartingDate:                       "1970-01-01",
			EndingDate:                         "2038-01-19",
		},
		StatusConfirmation:           "01",
		UniqueNumberOfIssuedDocument: "asd123",
		CompetentInstitution: socialsecurity.PDA1CompetentInstitution{
			InstitutionID:   fmt.Sprintf("%s:%s", s.Client.randomISO31661Alpha2EU(), gofakeit.Numerify("####")),
			InstitutionName: gofakeit.Company(),
			CountryCode:     s.Client.randomISO31661Alpha2EU(),
		},
	}

	return doc.Marshal()

	//jsonBytes, err := json.Marshal(doc)
	//if err != nil {
	//	panic(err)
	//}

	//reply := map[string]any{}
	//if err := json.Unmarshal(jsonBytes, &reply); err != nil {
	//	panic(err)
	//}

	//return reply
}
