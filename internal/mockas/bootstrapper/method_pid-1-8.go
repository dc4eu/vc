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

type pid18Client struct {
	client         *Client
	documents      map[string]*vcclient.UploadRequest
	credentialType string
	pidUsers       map[string]*vcclient.AddPIDRequest
}

func NewPID18Client(ctx context.Context, client *Client) (*pid18Client, error) {
	pidClient := &pid18Client{
		client:         client,
		documents:      map[string]*vcclient.UploadRequest{},
		credentialType: "pid-1-8",
	}

	return pidClient, nil
}

func (c *pid18Client) readPidUserFile(sourceFilePath string) error {
	f, err := os.Open(filepath.Clean(sourceFilePath))
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

func (c *pid18Client) makeSourceData(sourceFilePath string) error {
	if err := c.readPidUserFile(sourceFilePath); err != nil {
		return fmt.Errorf("read pid user file: %w", err)
	}

	for pidNumber, id := range c.pidUsers {
		c.documents[pidNumber] = &vcclient.UploadRequest{}

		c.documents[pidNumber].DocumentData = map[string]any{
			"given_name":                 id.Identity.GivenName,
			"family_name":                id.Identity.FamilyName,
			"birth_date":                 id.Identity.BirthDate,
			"birth_place":                id.Identity.BirthPlace,
			"nationality":                id.Identity.Nationality,
			"issuing_authority":          id.Identity.IssuingAuthority,
			"issuing_country":            id.Identity.IssuingCountry,
			"expiry_date":                id.Identity.ExpiryDate,
			"authentic_source_person_id": id.Identity.AuthenticSourcePersonID,
			"arf":                        "1.8",
		}

		c.documents[pidNumber].Meta = &model.MetaData{
			AuthenticSource: "PID_Provider:00001",
			DocumentVersion: "1.0.0",
			VCT:             model.CredentialTypeUrnEudiPidARG181,
			DocumentID:      fmt.Sprintf("document_id_pid_arf_1_8_%s", pidNumber),
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
					"description": "Personal Identification Document",
				},
				"sv": map[string]any{
					"beskrivning": "Personligt identifikationsdokument",
				},
			},
		}

		c.documents[pidNumber].Identities = []model.Identity{*id.Identity}

		c.documents[pidNumber].DocumentDataVersion = "1.0.0"
	}

	return nil
}

func (c *pid18Client) save2Disk() error {
	b, err := json.MarshalIndent(c.documents, "", "  ")
	if err != nil {
		return err
	}

	filePath := filepath.Join("../../../bootstrapping", fmt.Sprintf("%s.json", c.credentialType))

	if err := os.WriteFile(filepath.Clean(filePath), b, 0600); err != nil {
		return err
	}

	return nil
}
