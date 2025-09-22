package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"vc/pkg/model"
	"vc/pkg/pid"
	"vc/pkg/vcclient"
)

type pidClient struct {
	client         *Client
	documents      map[string]*vcclient.UploadRequest
	credentialType string
	pidUsers       map[string]*vcclient.AddPIDRequest
}

func NewPIDClient(ctx context.Context, client *Client) (*pidClient, error) {
	pidClient := &pidClient{
		client:         client,
		documents:      map[string]*vcclient.UploadRequest{},
		credentialType: "pid",
	}

	return pidClient, nil
}

func (c *pidClient) readPidUserFile(sourceFilePath string) error {
	f, err := os.Open(sourceFilePath)
	if err != nil {
		return fmt.Errorf("open pid user file: %w", err)
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&c.pidUsers); err != nil {
		return fmt.Errorf("decode pid user file: %w", err)
	}

	return nil
}

func (c *pidClient) makeSourceData(sourceFilePath string) error {
	if err := c.readPidUserFile("../../../bootstrapping/pid_user.json"); err != nil {
		return fmt.Errorf("read pid user file: %w", err)
	}

	for pidNumber, id := range c.pidUsers {
		c.documents[pidNumber] = &vcclient.UploadRequest{}

		documentData := pid.Document{
			Identity: &model.Identity{
				GivenName:        id.Identity.GivenName,
				FamilyName:       id.Identity.FamilyName,
				BirthDate:        id.Identity.BirthDate,
				BirthPlace:       id.Identity.BirthPlace,
				Nationality:      id.Identity.Nationality,
				ExpiryDate:       id.Identity.ExpiryDate,
				IssuingAuthority: id.Identity.IssuingAuthority,
				IssuingCountry:   id.Identity.IssuingCountry,
			},
		}

		var err error
		c.documents[pidNumber].DocumentData, err = documentData.Marshal()
		if err != nil {
			return err
		}

		c.documents[pidNumber].Meta = &model.MetaData{
			AuthenticSource: id.Meta.AuthenticSource,
			DocumentVersion: "1.0.0",
			DocumentType:    id.Meta.DocumentType,
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

		c.documents[pidNumber].Identities = []model.Identity{*id.Identity}

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
