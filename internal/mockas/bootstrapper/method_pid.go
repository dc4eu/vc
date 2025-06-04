package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"vc/pkg/model"
	"vc/pkg/vcclient"
)

type pidClient struct {
	client         *Client
	documents      map[string]*vcclient.UploadRequest
	credentialType string
}

func NewPIDClient(ctx context.Context, client *Client) (*pidClient, error) {
	pda1Client := &pidClient{
		client:         client,
		documents:      map[string]*vcclient.UploadRequest{},
		credentialType: "pid",
	}

	return pda1Client, nil
}

func (c *pidClient) makeSourceData(sourceFilePath string) error {
	for pidNumber, id := range c.client.identities {
		c.documents[pidNumber] = &vcclient.UploadRequest{}

		documentData := model.Identity{
			GivenName:        id.Identities[0].GivenName,
			FamilyName:       id.Identities[0].FamilyName,
			BirthDate:        id.Identities[0].BirthDate,
			BirthPlace:       id.Identities[0].BirthPlace,
			Nationality:      id.Identities[0].Nationality,
			ExpiryDate:       id.Identities[0].ExpiryDate,
			IssuingAuthority: id.Identities[0].IssuingAuthority,
			IssuingCountry:   id.Identities[0].IssuingCountry,
		}

		var err error
		c.documents[pidNumber].DocumentData, err = documentData.Marshal()
		if err != nil {
			return err
		}

		c.documents[pidNumber].Meta = &model.MetaData{
			AuthenticSource: "PID:00001",
			DocumentVersion: "1.0.0",
			DocumentType:    model.CredentialTypeUrnEudiPid1,
			DocumentID:      fmt.Sprintf("document_id_pid_%s", pidNumber),
			RealData:        false,
			Collect: &model.Collect{
				ID:         fmt.Sprintf("collect_id_pid_%s", pidNumber),
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
					"documentType": "PID",
				},
				"sv": map[string]any{
					"documentType": "PID",
				},
			},
		}

		c.documents[pidNumber].Identities = id.Identities

		c.documents[pidNumber].DocumentDataVersion = "1.0.0"
	}

	return nil
}

func (c *pidClient) save2Disk() error {
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
