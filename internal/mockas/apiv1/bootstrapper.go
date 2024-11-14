package apiv1

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"vc/pkg/ehic"
	"vc/pkg/model"
	"vc/pkg/pda1"
)

type person struct {
	authenticSourcePersonID string
	firstName               string
	lastName                string
	dateOfBirth             string
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
						EmployerID: "f7c317dc",
						TypeOfID:   "01",
					},
				},
			},
		},
		PlacesOfWork: []pda1.PlacesOfWork{
			{
				AFixedPlaceOfWorkExist: false,
				CountryWork:            p.workAddress.Country,
				PlaceOfWork: []pda1.PlaceOfWork{
					{
						CompanyVesselName: fmt.Sprintf("vessel_name_%s", strings.ToLower(p.nationality[0])),
						FlagStateHomeBase: p.workAddress.Country,
						IDsOfCompany: []pda1.IDsOfCompany{
							{
								CompanyID: "3615c840",
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
			InstitutionID:   fmt.Sprintf("%s:1234", p.nationality[0]),
			InstitutionName: fmt.Sprintf("institution_name_%s", strings.ToLower(p.nationality[0])),
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
		},
		SocialSecurityPin: p.socialSecurityPin,
		PeriodEntitlement: ehic.PeriodEntitlement{
			StartingDate: "1970-01-01",
			EndingDate:   "2038-01-19",
		},
		DocumentID: fmt.Sprintf("document_id_%s", p.authenticSourcePersonID),
		CompetentInstitution: ehic.CompetentInstitution{
			InstitutionID:      fmt.Sprintf("%s:1234", p.workAddress.Country),
			InstitutionName:    fmt.Sprintf("institution_name_%s", strings.ToLower(p.nationality[0])),
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
			socialSecurityPin:       "98883123",
			nationality:             []string{"DE"},
			typeOfEmployment:        "02",
			workAddress:             address{Street: "Vurfelser Kaule 31", PostCode: "51427", Town: "Bergisch Gladbach", Country: "DE"},
			employmentAddress:       address{Street: "Hieronymusgasse 2", PostCode: "78462", Town: "Konstanz", Country: "DE"},
		},
		{
			authenticSourcePersonID: "13",
			firstName:               "Olivia",
			lastName:                "Eelman",
			dateOfBirth:             "1971-03-13",
			socialSecurityPin:       "097428358",
			nationality:             []string{"NL"},
			typeOfEmployment:        "02",
			workAddress:             address{Street: "Jansplein 49", PostCode: "6811 GD", Town: "Arnhem", Country: "NL"},
			employmentAddress:       address{Street: "Buytenparklaan 30", PostCode: "2717 AX", Town: "Zoetermeer", Country: "NL"},
		},
		{
			authenticSourcePersonID: "14",
			firstName:               "Patrick",
			lastName:                "Høgh-Nørgaard Iversen",
			dateOfBirth:             "1994-03-07",
			socialSecurityPin:       "449-49-2795",
			nationality:             []string{"DK"},
			typeOfEmployment:        "02",
			workAddress:             address{Street: "Nørregade 7", PostCode: "1165", Town: "København", Country: "DK"},
			employmentAddress:       address{Street: "Galgebakkevej 3", PostCode: "2630", Town: "Taastrup", Country: "DK"},
		},
	},
	"PDA1": {
		{
			authenticSourcePersonID: "20",
			firstName:               "Mats",
			lastName:                "Christiansen",
			dateOfBirth:             "1983-03-27",
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
			socialSecurityPin:       "12345",
			nationality:             []string{"SE"},
			typeOfEmployment:        "01",
			workAddress:             address{Street: "Idrottsgatan 2", PostCode: "753 33", Town: "Uppsala", Country: "SE"},
			employmentAddress:       address{Street: "Östra Storgatan 10A", PostCode: "611 34", Town: "Nyköping", Country: "SE"},
		},
		{
			authenticSourcePersonID: "23",
			firstName:               "Joep",
			lastName:                "Cicilia",
			dateOfBirth:             "1999-07-29",
			socialSecurityPin:       "753841605",
			nationality:             []string{"NL"},
			typeOfEmployment:        "01",
			workAddress:             address{Street: "Het Rond 6", PostCode: "3701 HS", Town: "Zeist", Country: "NL"},
			employmentAddress:       address{Street: "Oude Ebbingestraat 68", PostCode: "9712 HM", Town: "Groningen", Country: "NL"},
		},
		{
			authenticSourcePersonID: "24",
			firstName:               "Hollis",
			lastName:                "Hoeger",
			dateOfBirth:             "1983-05-05",
			socialSecurityPin:       "315-95-2501",
			nationality:             []string{"AT"},
			typeOfEmployment:        "01",
			workAddress:             address{Street: "Stumpergasse 48/8", PostCode: "1060", Town: "Wien", Country: "AT"},
			employmentAddress:       address{Street: "Franz-Josef-Platz 3", PostCode: "4810", Town: "Gmunden", Country: "AT"},
		},
	},
}

func (c *Client) bootstrapperConstructor(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

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
				AuthenticSource: fmt.Sprintf("authentic_source_%s", strings.ToLower(p.nationality[0])),
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
					ID:      "9da40dc0",
					Revoked: false,
					Reference: model.RevocationReference{
						AuthenticSource: fmt.Sprintf("authentic_source_%s", strings.ToLower(p.nationality[0])),
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
