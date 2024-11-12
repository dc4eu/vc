package apiv1

import (
	"context"
	"errors"
	"fmt"
	"vc/pkg/ehic"
	"vc/pkg/model"
	"vc/pkg/pda1"
)

type person struct {
	authenticSourcePersonID string
	firstName               string
	lastName                string
	dateOfBirth             string
	gender                  string
	socialSecurityPin       string
	nationality             []string
	typeOfEmployment        string
	workAddress             address
	employmentAddress       address
}

type address struct {
	Street   string
	PostCode string
	Town     string
	Country  string
}

func (p *person) bootstrapPDA1() (map[string]any, error) {
	doc := pda1.Document{
		Person: pda1.Person{
			Forename:    p.firstName,
			FamilyName:  p.lastName,
			DateOfBirth: p.dateOfBirth,
			OtherElements: pda1.OtherElements{
				Sex:               p.gender,
				ForenameAtBirth:   p.firstName,
				FamilyNameAtBirth: p.lastName,
			},
		},
		SocialSecurityPin: p.socialSecurityPin,
		Nationality:       p.nationality,
		DetailsOfEmployment: []pda1.DetailsOfEmployment{
			{
				TypeOfEmployment: "01",
				Name:             "Corp inc.",
				Address: pda1.AddressWithCountry{
					Street:   p.employmentAddress.Street,
					PostCode: p.employmentAddress.PostCode,
					Town:     p.employmentAddress.Town,
					Country:  p.employmentAddress.Country,
				},
				IDsOfEmployer: []pda1.IDsOfEmployer{
					{
						EmployerID: "f7c317dc-9da3-11ef-ad15-2ff7d0db967b",
						TypeOfID:   "01",
					},
				},
			},
		},
		PlacesOfWork: []pda1.PlacesOfWork{
			{
				NoFixedPlaceOfWorkExist: false,
				CountryWork:             p.workAddress.Country,
				PlaceOfWork: []pda1.PlaceOfWork{
					{
						CompanyVesselName: fmt.Sprintf("vessel_name_%s", p.workAddress.Country),
						FlagStateHomeBase: p.workAddress.Country,
						IDsOfCompany: []pda1.IDsOfCompany{
							{
								CompanyID: "3615c840-9da4-11ef-ab82-5bd130b1f1e2",
								TypeOfID:  "01",
							},
						},
						Address: pda1.Address{
							Street:   p.workAddress.Street,
							PostCode: p.workAddress.PostCode,
							Town:     p.workAddress.Town,
						},
					},
				},
			},
		},
		DecisionLegislationApplicable: pda1.DecisionLegislationApplicable{
			MemberStateWhichLegislationApplies: p.workAddress.Country,
			TransitionalRuleApply:              false,
			StartingDate:                       "1970-01-01",
			EndingDate:                         "2038-01-19",
		},
		StatusConfirmation:           "01",
		UniqueNumberOfIssuedDocument: "asd123",
		CompetentInstitution: pda1.CompetentInstitution{
			InstitutionID:   fmt.Sprintf("%s:1234", p.workAddress.Country),
			InstitutionName: fmt.Sprintf("institution_name_%s", p.workAddress.Country),
			CountryCode:     p.workAddress.Country,
		},
	}

	return doc.Marshal()
}

func (p *person) bootstrapEHIC() (map[string]any, error) {
	doc := ehic.Document{
		Subject: ehic.Subject{
			Forename:    p.firstName,
			FamilyName:  p.lastName,
			DateOfBirth: p.dateOfBirth,
			OtherElements: ehic.OtherElements{
				Sex:               p.gender,
				ForenameAtBirth:   p.firstName,
				FamilyNameAtBirth: p.lastName,
			},
		},
		SocialSecurityPin: p.socialSecurityPin,
		PeriodEntitlement: ehic.PeriodEntitlement{
			StartingDate: "1970-01-01",
			EndingDate:   "2038-01-19",
		},
		DocumentID: fmt.Sprintf("document_id_%s", p.authenticSourcePersonID),
		CompetentInstitution: ehic.CompetentInstitution{
			InstitutionID:      fmt.Sprintf("%s:1234", p.workAddress.Country),
			InstitutionName:    fmt.Sprintf("institution_name_%s", p.workAddress.Country),
			InstitutionCountry: p.workAddress.Country,
		},
	}
	return doc.Marshal()

}

var persons = map[string][]person{
	"EHIC": {
		{
			authenticSourcePersonID: "10",
			firstName:               "Carlos",
			lastName:                "Castaneda",
			dateOfBirth:             "1970-01-10",
			gender:                  "01",
			socialSecurityPin:       "12345",
			nationality:             []string{"SE"},
			typeOfEmployment:        "01",
			workAddress:             address{Street: "Drottninggatan 1", PostCode: "12345", Town: "Stockholm", Country: "SE"},
			employmentAddress:       address{Street: "Kungsgatan 1", PostCode: "12346", Town: "Stockholm", Country: "SE"},
		},
		{

			authenticSourcePersonID: "11",
			firstName:               "Lenna",
			lastName:                "Howell",
			dateOfBirth:             "1935-02-21",
			gender:                  "02",
			socialSecurityPin:       "12357",
			nationality:             []string{"AT"},
			typeOfEmployment:        "01",
			workAddress:             address{Street: "Obere Hauptstraße 1", PostCode: "12346", Town: "Wien", Country: "AT"},
			employmentAddress:       address{Street: "Untere Hauptstraße 1", PostCode: "12347", Town: "Wien", Country: "AT"},
		},
		{
			authenticSourcePersonID: "12",
			firstName:               "Ute",
			lastName:                "Anderson",
			dateOfBirth:             "1967-03-21",
			gender:                  "02",
			socialSecurityPin:       "98883123",
			nationality:             []string{"DE"},
			typeOfEmployment:        "02",
			workAddress:             address{Street: "Vurfelser Kaule 31", PostCode: "51427", Town: "Bergisch Gladbach", Country: "DE"},
			employmentAddress:       address{Street: "Hieronymusgasse 2", PostCode: "78462", Town: "Konstanz", Country: "DE"},
		},
	},
	"PDA1": {
		{
			authenticSourcePersonID: "20",
			firstName:               "Mats",
			lastName:                "Christiansen",
			dateOfBirth:             "1983-03-27",
			gender:                  "01",
			socialSecurityPin:       "98123",
			nationality:             []string{"DK"},
			typeOfEmployment:        "02",
			workAddress:             address{Street: "Møllestien 2", PostCode: "12332", Town: "Aarhus", Country: "DK"},
			employmentAddress:       address{Street: "Møllestien 2", PostCode: "12332", Town: "Aarhus", Country: "DK"},
		},
		{
			authenticSourcePersonID: "21",
			firstName:               "Aldrich",
			lastName:                "Derichs",
			dateOfBirth:             "1971-05-25",
			gender:                  "01",
			socialSecurityPin:       "98123123",
			nationality:             []string{"DE"},
			typeOfEmployment:        "02",
			workAddress:             address{Street: "Petzoldstrasse 2", PostCode: "03042", Town: "Cottbus", Country: "DE"},
			employmentAddress:       address{Street: "Masurenallee 33", PostCode: "47055", Town: "Duisburg", Country: "DE"},
		},
		{
			authenticSourcePersonID: "22",
			firstName:               "Algot",
			lastName:                "Holmberg",
			dateOfBirth:             "1955-11-25",
			gender:                  "01",
			socialSecurityPin:       "12345",
			nationality:             []string{"SE"},
			typeOfEmployment:        "01",
			workAddress:             address{Street: "Idrottsgatan 2", PostCode: "753 33", Town: "Uppsala", Country: "SE"},
			employmentAddress:       address{Street: "Ostra Storgatan 10A", PostCode: "611 34", Town: "Nykoping", Country: "SE"},
		},
	},
}

func (c *Client) bootstrapperConstructor(ctx context.Context) error {
	for documentType, document := range persons {
		for _, p := range document {
			var documentData = map[string]any{}
			switch documentType {
			case "EHIC":
				var err error
				documentData, err = p.bootstrapEHIC()
				if err != nil {
					return err
				}
			case "PDA1":
				var err error
				documentData, err = p.bootstrapPDA1()
				if err != nil {
					return err
				}
			}
			meta := &model.MetaData{
				AuthenticSource: fmt.Sprintf("authentic_source_%s", documentType),
				DocumentType:    documentType,
				DocumentID:      fmt.Sprintf("document_id_%s", p.authenticSourcePersonID),
				DocumentVersion: "1.0.0",
				RealData:        false,
				Collect: &model.Collect{
					ID:         fmt.Sprintf("collect_id_%s", p.authenticSourcePersonID),
					ValidUntil: 2147520172,
				},
				CredentialValidFrom: 1,
				CredentialValidTo:   2147520172,
				Revocation: &model.Revocation{
					ID:      "9da40dc0-9dd4-11ef-9569-efda8acf5ac4",
					Revoked: false,
					Reference: model.RevocationReference{
						AuthenticSource: fmt.Sprintf("authentic_source_%s", documentType),
						DocumentType:    documentType,
						DocumentID:      fmt.Sprintf("document_id_%s", p.authenticSourcePersonID),
					},
				},
			}

			identities := []model.Identity{
				{
					AuthenticSourcePersonID: p.authenticSourcePersonID,
					Schema: &model.IdentitySchema{
						Name:    p.workAddress.Country,
						Version: "1.0.0",
					},
					FamilyName: p.lastName,
					GivenName:  p.firstName,
					BirthDate:  p.dateOfBirth,
				},
			}

			documentDisplay := &model.DocumentDisplay{
				Version: "1.0.0",
				Type:    documentType,
				DescriptionStructured: map[string]any{
					"en": "issuer",
					"sv": "utfärdare",
				},
			}

			mockUpload := uploadMock{
				Meta:                meta,
				Identities:          identities,
				DocumentDisplay:     documentDisplay,
				DocumentData:        documentData,
				DocumentDataVersion: "1.0.0",
			}

			c.deterministicMocks = append(c.deterministicMocks, mockUpload)

		}
	}
	return nil

}

func (c *Client) bootstrapper(ctx context.Context) error {
	if err := c.bootstrapperConstructor(ctx); err != nil {
		return err
	}

	for _, mockUpload := range c.deterministicMocks {
		c.log.Debug("uploading bootstrap mock", "authentic_source_person_id", mockUpload.Identities[0].AuthenticSourcePersonID)

		resp, err := c.uploader(ctx, &mockUpload)
		if err != nil {
			c.log.Error(err, "failed to upload", "mockUpload", mockUpload)
			return err
		}

		if resp.StatusCode != 200 {
			return errors.New("upload failed")
		}
	}

	return nil
}
