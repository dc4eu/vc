package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"vc/pkg/model"
	"vc/pkg/socialsecurity"

	"github.com/xuri/excelize/v2"
)

type ehicClient struct {
	client         *Client
	documents      map[string]*model.CompleteDocument
	credentialType string
}

func NewEHICClient(ctx context.Context, client *Client) (*ehicClient, error) {
	ehicClient := &ehicClient{
		client:         client,
		documents:      map[string]*model.CompleteDocument{},
		credentialType: "ehic",
	}
	return ehicClient, nil
}

func (c *ehicClient) makeSourceData(sourceFilePath string) error {
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

	ehicRows, err := f.GetRows("EHIC")
	if err != nil {
		return err
	}

	for _, row := range ehicRows {
		pid := row[0]
		if pid == "" || pid == "pid_id" {
			continue
		}

		c.documents[pid] = &model.CompleteDocument{}

		SocialSecurityPin := row[4]
		startDate := row[5]
		endDate := row[6]

		CardNumber := row[7]
		InstitutionID := row[8]
		InstitutionName := row[9]
		InstitutionCountry := row[10]

		user, ok := c.client.identities[pid]
		if !ok {
			return fmt.Errorf("no user found for pid %s", pid)
		}

		document := &socialsecurity.EHICDocument{
			Subject: socialsecurity.Subject{
				Forename:    user.Identities[0].GivenName,
				FamilyName:  user.Identities[0].FamilyName,
				DateOfBirth: user.Identities[0].BirthDate,
			},
			SocialSecurityPin: SocialSecurityPin,
			PeriodEntitlement: socialsecurity.PeriodEntitlement{
				StartingDate: startDate,
				EndingDate:   endDate,
			},
			DocumentID: CardNumber,
			CompetentInstitution: socialsecurity.CompetentInstitution{
				InstitutionID:      InstitutionID,
				InstitutionName:    InstitutionName,
				InstitutionCountry: InstitutionCountry,
			},
		}

		var err error
		c.documents[pid].DocumentData, err = document.Marshal()
		if err != nil {
			return err
		}

		c.documents[pid].Meta = &model.MetaData{
			AuthenticSource: row[2],
			DocumentVersion: "1.0.0",
			DocumentType:    "EHIC",
			DocumentID:      fmt.Sprintf("document_id_ehic_%s", row[0]),
			RealData:        false,
			Collect: &model.Collect{
				ID:         fmt.Sprintf("collect_id_ehic_%s", row[0]),
				ValidUntil: 0,
			},
			Revocation:                &model.Revocation{},
			CredentialValidFrom:       0,
			CredentialValidTo:         0,
			DocumentDataValidationRef: "",
		}

		c.documents[pid].DocumentDisplay = &model.DocumentDisplay{
			Version: "1.0.0",
			Type:    "secure",
			DescriptionStructured: map[string]any{
				"en": map[string]any{
					"documentType": "EHIC",
				},
				"sv": map[string]any{
					"documentType": "EHIC",
				},
			},
		}

	}

	return nil
}

func (c *ehicClient) save2Disk() error {
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
