package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"vc/pkg/datastoreclient"
	"vc/pkg/model"
	"vc/pkg/socialsecurity"

	"github.com/xuri/excelize/v2"
)

type pda1Client struct {
	client         *Client
	documents      map[string]*datastoreclient.UploadRequest
	credentialType string
}

func NewPDA1Client(ctx context.Context, client *Client) (*pda1Client, error) {
	c := &pda1Client{
		client:         client,
		documents:      map[string]*datastoreclient.UploadRequest{},
		credentialType: "pda1",
	}

	return c, nil
}

func (c *pda1Client) makeSourceData(sourceFilePath string) error {
	f, err := excelize.OpenFile(sourceFilePath)
	if err != nil {
		return err
	}
	defer func() {
		// Close the spreadsheet.
		if err := f.Close(); err != nil {
			panic(err)
		}
	}()

	pda1Rows, err := f.GetRows("PDA1")
	if err != nil {
		return err
	}

	for _, row := range pda1Rows {
		pidNumber := row[0]
		if pidNumber == "" || pidNumber == "pid_id" || pidNumber == "pid_id (Spalte H, nach pda1_issuing_country)" {
			continue
		}

		c.documents[pidNumber] = &datastoreclient.UploadRequest{}

		identity, ok := c.client.identities[pidNumber]
		if !ok {
			return fmt.Errorf("no user found for pid %s", pidNumber)
		}

		document := &socialsecurity.PDA1Document{
			SocialSecurityPin: row[6],
			Nationality:       []string{row[7]},
			DetailsOfEmployment: []socialsecurity.DetailsOfEmployment{
				{
					TypeOfEmployment: row[8],
					Name:             row[9],
					Address: socialsecurity.AddressWithCountry{
						Street:   row[12],
						PostCode: row[14],
						Town:     row[13],
						Country:  row[15],
					},
					IDsOfEmployer: []socialsecurity.IDsOfEmployer{
						{
							EmployerID: row[10],
							TypeOfID:   row[11],
						},
					},
				},
			},
			PlacesOfWork: []socialsecurity.PlacesOfWork{
				{
					AFixedPlaceOfWorkExist: false,
					CountryWork:            row[16],
					PlaceOfWork: []socialsecurity.PlaceOfWork{
						{
							CompanyVesselName: "",
							FlagStateHomeBase: row[21],
							IDsOfCompany: []socialsecurity.IDsOfCompany{
								{
									CompanyID: row[18],
									TypeOfID:  row[19],
								},
							},
							Address: socialsecurity.Address{
								Street:   row[22],
								PostCode: row[24],
								Town:     row[23],
							},
						},
					},
				},
			},
			DecisionLegislationApplicable: socialsecurity.DecisionLegislationApplicable{
				MemberStateWhichLegislationApplies: row[26],
				TransitionalRuleApply:              false,
				StartingDate:                       row[28],
				EndingDate:                         row[29],
			},
			StatusConfirmation:           row[30],
			UniqueNumberOfIssuedDocument: "",
			CompetentInstitution: socialsecurity.PDA1CompetentInstitution{
				InstitutionID:   row[32],
				InstitutionName: row[33],
				CountryCode:     row[34],
			},
		}

		var err error
		c.documents[pidNumber].DocumentData, err = document.Marshal()
		if err != nil {
			return err
		}

		c.documents[pidNumber].Meta = &model.MetaData{
			AuthenticSource: row[3],
			DocumentVersion: "1.0.0",
			DocumentType:    "PDA1",
			DocumentID:      fmt.Sprintf("document_id_pda1_%s", row[0]),
			RealData:        false,
			Collect: &model.Collect{
				ID:         fmt.Sprintf("collect_id_pda1_%s", row[0]),
				ValidUntil: 0,
			},
			Revocation:                &model.Revocation{},
			CredentialValidFrom:       0,
			CredentialValidTo:         0,
			DocumentDataValidationRef: "",
		}

		c.documents[pidNumber].DocumentDisplay = &model.DocumentDisplay{
			Version: "1.0.0",
			Type:    "secure",
			DescriptionStructured: map[string]any{
				"en": map[string]any{
					"documentType": "PDA1",
				},
				"sv": map[string]any{
					"documentType": "PDA1",
				},
			},
		}

		c.documents[pidNumber].Identities = identity.Identities

		c.documents[pidNumber].DocumentDataVersion = "1.0.0"

	}

	return nil
}

func (c *pda1Client) save2Disk() error {
	b, err := json.MarshalIndent(c.documents, "", "  ")
	if err != nil {
		return err
	}

	filePath := filepath.Join("../../../bootstrapping", fmt.Sprintf("%s.json", c.credentialType))

	if err := os.WriteFile(filePath, b, 0644); err != nil {
		return err
	}

	return nil
}
