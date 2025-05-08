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

type diplomaClient struct {
	client              *Client
	documents           map[string]*vcclient.UploadRequest
	credentialType      string
	exampleELM          []map[string]any
	exampleELMFilePaths []string
}

func NewDiplomaClient(ctx context.Context, client *Client) (*diplomaClient, error) {
	diplomaClient := &diplomaClient{
		client:     client,
		documents:  map[string]*vcclient.UploadRequest{},
		exampleELM: []map[string]any{},
		exampleELMFilePaths: []string{
			filepath.Join("../../../standards", "education_credential", "diploma", "HE-diploma-9ad88a95-2f9a-4a1d-9e08-a61e213a3eac-degreeHBO-M.xml.json"),
		},
		credentialType: "diploma",
	}

	if err := diplomaClient.loadExampleFiles(); err != nil {
		return nil, fmt.Errorf("read document data file: %w", err)
	}

	return diplomaClient, nil
}

func (c *diplomaClient) makeSourceData(sourceFilePath string) error {
	for pidNumber, id := range c.client.identities {
		c.documents[pidNumber] = &vcclient.UploadRequest{}

		documentData, err := c.getOneDocumentData(pidNumber)
		if err != nil {
			return fmt.Errorf("get document data: %w", err)
		}
		c.documents[pidNumber].DocumentData = documentData

		c.documents[pidNumber].Meta = &model.MetaData{
			AuthenticSource: "DIPLOMA:00001",
			DocumentVersion: "1.0.0",
			DocumentType:    "Diploma",
			DocumentID:      fmt.Sprintf("document_id_diploma_%s", pidNumber),
			RealData:        false,
			Collect: &model.Collect{
				ID:         fmt.Sprintf("collect_id_diploma_%s", pidNumber),
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
					"documentType": "Diploma",
				},
				"sv": map[string]any{
					"documentType": "Diploma",
				},
			},
		}

		c.documents[pidNumber].Identities = id.Identities

		c.documents[pidNumber].DocumentDataVersion = "1.0.0"
	}

	return nil
}

func (c *diplomaClient) save2Disk() error {
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

func (c *diplomaClient) loadExampleFiles() error {
	for _, filePath := range c.exampleELMFilePaths {
		b, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}

		doc := map[string]any{}
		if err := json.Unmarshal(b, &doc); err != nil {
			return err
		}

		c.exampleELM = append(c.exampleELM, doc)
	}

	return nil
}

func (c *diplomaClient) getOneDocumentData(pidNumber string) (map[string]any, error) {
	if len(c.exampleELM) == 0 {
		return nil, fmt.Errorf("no example ELM files loaded")
	}
	if len(c.exampleELM) == 1 {
		return c.exampleELM[0], nil
	} else if len(c.exampleELM) > 1 {
		return nil, fmt.Errorf("multiple example ELM files not supported yet")
	}

	return nil, nil

}
