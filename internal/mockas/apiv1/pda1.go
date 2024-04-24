package apiv1

import (
	"context"
	"encoding/json"
	"time"
	"vc/pkg/pda1"

	"github.com/brianvoe/gofakeit/v6"
)

// PDA1Service holds the PDA1 document type
type PDA1Service struct {
	Client *Client
}

func (s *PDA1Service) random(ctx context.Context, person *gofakeit.PersonInfo) map[string]any {
	doc := pda1.Document{
		PersonalDetails: pda1.Section1{
			PersonalIdentificationNumber: gofakeit.Numerify("##########"),
			Sex:                          gofakeit.RandomString([]string{"01", "02", "98", "99"}),
			Surname:                      person.LastName,
			Forenames:                    person.FirstName,
			SurnameAtBirth:               person.LastName,
			DateBirth:                    gofakeit.Date().String(),
			Nationality:                  s.Client.randomISO31661Alpha2EU(),
			PlaceBirth: pda1.BirthPlaceType{
				Town:        gofakeit.City(),
				Region:      gofakeit.TimeZoneRegion(),
				CountryCode: s.Client.randomISO31661Alpha2EU(),
			},
			StateOfResidenceAddress: pda1.AddressType{
				BuildingName: gofakeit.BuzzWord() + "building",
				StreetNo:     gofakeit.StreetNumber(),
				PostCode:     gofakeit.Zip(),
				Town:         gofakeit.City(),
				Region:       gofakeit.State(),
				CountryCode:  s.Client.randomISO31661Alpha2EU(), // should be short version
			},
			StateOfStayAddress: pda1.AddressType{
				CountryCode: s.Client.randomISO31661Alpha2EU(),
			},
		},
		MemberStateLegislation: pda1.Section2{
			MemberStateWhichLegislationApplies: s.Client.randomISO31661Alpha2EU(),
			StartingDate:                       time.Now(),
			EndingDate:                         time.Now().Add(time.Hour * 24 * 365 * 5),
			CertificateForDurationActivity:     false,
			DeterminationProvisional:           false,
			TransitionRulesApplyAsEC8832004:    false,
		},
		StatusConfirmation: pda1.Section3{
			PostedEmployedPerson:         false,
			EmployedTwoOrMoreStates:      false,
			PostedSelfEmployedPerson:     false,
			SelfEmployedTwoOrMoreStates:  false,
			CivilServant:                 false,
			ContractStaff:                false,
			Mariner:                      true,
			EmployedAndSelfEmployed:      false,
			CivilAndEmployedSelfEmployed: false,
			FlightCrewMember:             false,
			Exception:                    false,
			ExceptionDescription:         "",
			WorkingInStateUnder21:        false,
		},
		EmploymentDetails: pda1.Section4{
			Employee:                          false,
			SelfEmployedActivity:              false,
			EmployerSelfEmployedActivityCodes: []string{},
			NameBusinessName:                  gofakeit.Company(),
			RegisteredAddress: pda1.AddressType{
				BuildingName: "",
				StreetNo:     gofakeit.StreetNumber(),
				PostCode:     gofakeit.Zip(),
				Town:         gofakeit.City(),
				Region:       gofakeit.State(),
				CountryCode:  s.Client.randomISO31661Alpha2EU(),
			},
		},
		ActivityEmploymentDetails: pda1.Section5{
			WorkPlaceNames:            []pda1.WorkPlaceNameType{},
			WorkPlaceNamesBlob:        gofakeit.Company(),
			WorkPlaceAddresses:        []pda1.WorkPlaceAddressType{},
			WorkPlaceAddressesBlob:    gofakeit.Address().Address,
			NoFixedAddress:            false,
			NoFixedAddressDescription: "",
		},
		CompletingInstitution: pda1.Section6{
			Name: gofakeit.Company(),
			Address: pda1.AddressType{
				CountryCode: s.Client.randomISO31661Alpha2EU(),
			},
			InstitutionID: gofakeit.Numerify("##########"),
			OfficeFaxNo:   gofakeit.Phone(),
			OfficePhoneNo: gofakeit.Phone(),
			Email:         gofakeit.Email(),
			Date:          time.Now(),
			Signature:     "",
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
