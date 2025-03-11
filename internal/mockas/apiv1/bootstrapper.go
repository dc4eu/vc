package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"vc/pkg/ehic"
	"vc/pkg/elm"
	"vc/pkg/model"
	"vc/pkg/pda1"
)

type person struct {
	AuthenticSourcePersonID string      `json:"authentic_source_person_id,omitempty"`
	FirstName               string      `json:"first_name,omitempty"`
	LastName                string      `json:"last_name,omitempty"`
	DateOfBirth             string      `json:"date_of_birth,omitempty"`
	SocialSecurityPin       string      `json:"social_security_pin,omitempty"`
	Nationality             []string    `json:"national,omitempty"`
	TypeOfEmployment        string      `json:"type_of_employment,omitempty"`
	WorkAddress             *address    `json:"work_address,omitempty"`
	EmploymentAddress       *address    `json:"employment_address,omitempty"`
	Ehic                    *personEhic `json:"ehic,omitempty"`
}

type personEhic struct {
	CardNumber string `json:"card_number,omitempty"`
	StartDate  string `json:"start_date,omitempty"`
	EndDate    string `json:"end_date,omitempty"`
}

type address struct {
	Street   string `json:"street,omitempty"`
	PostCode string `json:"post_code,omitempty"`
	Town     string `json:"town,omitempty"`
	Country  string `json:"country,omitempty"`
}

func (p *person) bootstrapPDA1() (map[string]any, error) {
	doc := pda1.Document{
		SocialSecurityPin: p.SocialSecurityPin,
		Nationality:       p.Nationality,
		DetailsOfEmployment: []pda1.DetailsOfEmployment{
			{
				TypeOfEmployment: "01",
				Name:             "Corp inc.",
				Address: pda1.AddressWithCountry{
					Street:   p.EmploymentAddress.Street,
					PostCode: p.EmploymentAddress.PostCode,
					Town:     p.EmploymentAddress.Town,
					Country:  p.EmploymentAddress.Country,
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
				CountryWork:            p.WorkAddress.Country,
				PlaceOfWork: []pda1.PlaceOfWork{
					{
						CompanyVesselName: fmt.Sprintf("vessel_name_%s", strings.ToLower(p.Nationality[0])),
						FlagStateHomeBase: p.WorkAddress.Country,
						IDsOfCompany: []pda1.IDsOfCompany{
							{
								CompanyID: "3615c840",
								TypeOfID:  "01",
							},
						},
						Address: pda1.Address{
							Street:   p.WorkAddress.Street,
							PostCode: p.WorkAddress.PostCode,
							Town:     p.WorkAddress.Town,
						},
					},
				},
			},
		},
		DecisionLegislationApplicable: pda1.DecisionLegislationApplicable{
			MemberStateWhichLegislationApplies: p.WorkAddress.Country,
			TransitionalRuleApply:              false,
			StartingDate:                       "1970-01-01",
			EndingDate:                         "2038-01-19",
		},
		StatusConfirmation:           "01",
		UniqueNumberOfIssuedDocument: "asd123",
		CompetentInstitution: pda1.CompetentInstitution{
			InstitutionID:   fmt.Sprintf("%s:1234", p.Nationality[0]),
			InstitutionName: fmt.Sprintf("institution_name_%s", strings.ToLower(p.Nationality[0])),
			CountryCode:     p.WorkAddress.Country,
		},
	}

	return doc.Marshal()
}

func (p *person) bootstrapEHIC() (map[string]any, error) {
	doc := ehic.Document{
		Subject: ehic.Subject{
			Forename:    p.FirstName,
			FamilyName:  p.LastName,
			DateOfBirth: p.DateOfBirth,
		},
		SocialSecurityPin: p.SocialSecurityPin,
		PeriodEntitlement: ehic.PeriodEntitlement{
			StartingDate: "1970-01-01",
			EndingDate:   "2038-01-19",
		},
		DocumentID: fmt.Sprintf("document_id_%s", p.AuthenticSourcePersonID),
		CompetentInstitution: ehic.CompetentInstitution{
			InstitutionID:      fmt.Sprintf("%s:1234", p.WorkAddress.Country),
			InstitutionName:    fmt.Sprintf("institution_name_%s", strings.ToLower(p.Nationality[0])),
			InstitutionCountry: p.WorkAddress.Country,
		},
	}

	return doc.Marshal()
}

func (p *person) bootstrapELM() (map[string]any, error) {
	doc := elm.Document{
		"firstName":   p.FirstName,
		"lastName":    p.LastName,
		"dateOfBirth": p.DateOfBirth,
	}

	return doc.Marshal()
}

var persons = map[string][]person{
	"EHIC": {
		{
			AuthenticSourcePersonID: "10",
			FirstName:               "Carlos",
			LastName:                "Castaneda",
			DateOfBirth:             "1970-01-10",
			SocialSecurityPin:       "12345",
			Nationality:             []string{"SE"},
			TypeOfEmployment:        "01",
			WorkAddress:             &address{Street: "Drottninggatan 1", PostCode: "12345", Town: "Stockholm", Country: "SE"},
			EmploymentAddress:       &address{Street: "Kungsgatan 1", PostCode: "12346", Town: "Stockholm", Country: "SE"},
		},
		{

			AuthenticSourcePersonID: "11",
			FirstName:               "Lenna",
			LastName:                "Howell",
			DateOfBirth:             "1935-02-21",
			SocialSecurityPin:       "12357",
			Nationality:             []string{"AT"},
			TypeOfEmployment:        "01",
			WorkAddress:             &address{Street: "Obere Hauptstraße 1", PostCode: "12346", Town: "Wien", Country: "AT"},
			EmploymentAddress:       &address{Street: "Untere Hauptstraße 1", PostCode: "12347", Town: "Wien", Country: "AT"},
		},
		{
			AuthenticSourcePersonID: "12",
			FirstName:               "Ute",
			LastName:                "Anderson",
			DateOfBirth:             "1967-03-21",
			SocialSecurityPin:       "98883123",
			Nationality:             []string{"DE"},
			TypeOfEmployment:        "02",
			WorkAddress:             &address{Street: "Vurfelser Kaule 31", PostCode: "51427", Town: "Bergisch Gladbach", Country: "DE"},
			EmploymentAddress:       &address{Street: "Hieronymusgasse 2", PostCode: "78462", Town: "Konstanz", Country: "DE"},
		},
		{
			AuthenticSourcePersonID: "13",
			FirstName:               "Olivia",
			LastName:                "Eelman",
			DateOfBirth:             "1971-03-13",
			SocialSecurityPin:       "097428358",
			Nationality:             []string{"NL"},
			TypeOfEmployment:        "02",
			WorkAddress:             &address{Street: "Jansplein 49", PostCode: "6811 GD", Town: "Arnhem", Country: "NL"},
			EmploymentAddress:       &address{Street: "Buytenparklaan 30", PostCode: "2717 AX", Town: "Zoetermeer", Country: "NL"},
		},
		{
			AuthenticSourcePersonID: "14",
			FirstName:               "Patrick",
			LastName:                "Høgh-Nørgaard Iversen",
			DateOfBirth:             "1994-03-07",
			SocialSecurityPin:       "449-49-2795",
			Nationality:             []string{"DK"},
			TypeOfEmployment:        "02",
			WorkAddress:             &address{Street: "Nørregade 7", PostCode: "1165", Town: "København", Country: "DK"},
			EmploymentAddress:       &address{Street: "Galgebakkevej 3", PostCode: "2630", Town: "Taastrup", Country: "DK"},
		},
	},
	"PDA1": {
		{
			AuthenticSourcePersonID: "20",
			FirstName:               "Mats",
			LastName:                "Christiansen",
			DateOfBirth:             "1983-03-27",
			SocialSecurityPin:       "98123",
			Nationality:             []string{"DK"},
			TypeOfEmployment:        "02",
			WorkAddress:             &address{Street: "Møllestien 2", PostCode: "12332", Town: "Aarhus", Country: "DK"},
			EmploymentAddress:       &address{Street: "Møllestien 2", PostCode: "12332", Town: "Aarhus", Country: "DK"},
		},
		{
			AuthenticSourcePersonID: "21",
			FirstName:               "Aldrich",
			LastName:                "Derichs",
			DateOfBirth:             "1971-05-25",
			SocialSecurityPin:       "98123123",
			Nationality:             []string{"DE"},
			TypeOfEmployment:        "02",
			WorkAddress:             &address{Street: "Petzoldstrasse 2", PostCode: "03042", Town: "Cottbus", Country: "DE"},
			EmploymentAddress:       &address{Street: "Masurenallee 33", PostCode: "47055", Town: "Duisburg", Country: "DE"},
		},
		{
			AuthenticSourcePersonID: "22",
			FirstName:               "Algot",
			LastName:                "Holmberg",
			DateOfBirth:             "1955-11-25",
			SocialSecurityPin:       "12345",
			Nationality:             []string{"SE"},
			TypeOfEmployment:        "01",
			WorkAddress:             &address{Street: "Idrottsgatan 2", PostCode: "753 33", Town: "Uppsala", Country: "SE"},
			EmploymentAddress:       &address{Street: "Östra Storgatan 10A", PostCode: "611 34", Town: "Nyköping", Country: "SE"},
		},
		{
			AuthenticSourcePersonID: "23",
			FirstName:               "Joep",
			LastName:                "Cicilia",
			DateOfBirth:             "1999-07-29",
			SocialSecurityPin:       "753841605",
			Nationality:             []string{"NL"},
			TypeOfEmployment:        "01",
			WorkAddress:             &address{Street: "Het Rond 6", PostCode: "3701 HS", Town: "Zeist", Country: "NL"},
			EmploymentAddress:       &address{Street: "Oude Ebbingestraat 68", PostCode: "9712 HM", Town: "Groningen", Country: "NL"},
		},
		{
			AuthenticSourcePersonID: "24",
			FirstName:               "Hollis",
			LastName:                "Hoeger",
			DateOfBirth:             "1983-05-05",
			SocialSecurityPin:       "315-95-2501",
			Nationality:             []string{"AT"},
			TypeOfEmployment:        "01",
			WorkAddress:             &address{Street: "Stumpergasse 48/8", PostCode: "1060", Town: "Wien", Country: "AT"},
			EmploymentAddress:       &address{Street: "Franz-Josef-Platz 3", PostCode: "4810", Town: "Gmunden", Country: "AT"},
		},
	},
	"ELM": {
		{
			AuthenticSourcePersonID: "30",
			FirstName:               "Magnus",
			LastName:                "Svensson",
			DateOfBirth:             "1983-03-27",
			Nationality:             []string{"SE"},
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
			case "ELM":
				b, err := os.ReadFile("standards/elm_3_2.json")
				if err != nil {
					return err
				}

				doc := map[string]any{}
				if err := json.Unmarshal(b, &doc); err != nil {
					return err
				}

				documentData = doc
			}
			meta := &model.MetaData{
				AuthenticSource: fmt.Sprintf("authentic_source_%s", strings.ToLower(p.Nationality[0])),
				DocumentType:    documentType,
				DocumentID:      fmt.Sprintf("document_id_%s", p.AuthenticSourcePersonID),
				DocumentVersion: "1.0.0",
				RealData:        false,
				Collect: &model.Collect{
					ID:         fmt.Sprintf("collect_id_%s", p.AuthenticSourcePersonID),
					ValidUntil: 2147520172,
				},
				CredentialValidFrom: 1,
				CredentialValidTo:   2147520172,
				Revocation: &model.Revocation{
					ID:      "9da40dc0",
					Revoked: false,
					Reference: model.RevocationReference{
						AuthenticSource: fmt.Sprintf("authentic_source_%s", strings.ToLower(p.Nationality[0])),
						DocumentType:    documentType,
						DocumentID:      fmt.Sprintf("document_id_%s", p.AuthenticSourcePersonID),
					},
				},
			}

			identities := []model.Identity{
				{
					AuthenticSourcePersonID: p.AuthenticSourcePersonID,
					Schema: &model.IdentitySchema{
						Name:    "DefaultSchema",
						Version: "1.0.0",
					},
					FamilyName: p.LastName,
					GivenName:  p.FirstName,
					BirthDate:  p.DateOfBirth,
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

	for _, mockUpload := range c.parisMocks {
		c.log.Debug("uploading paris mock", "authentic_source_person_id", mockUpload.Meta.DocumentType)

		document := &uploadMock{
			Meta:                mockUpload.Meta,
			Identities:          mockUpload.Identities,
			DocumentDisplay:     mockUpload.DocumentDisplay,
			DocumentData:        mockUpload.DocumentData,
			DocumentDataVersion: mockUpload.DocumentDataVersion,
		}

		resp, err := c.uploader(ctx, document)
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
