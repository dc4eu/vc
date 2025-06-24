package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"vc/pkg/model"
	"vc/pkg/vcclient"
)

type pidUsersClient struct {
	client            *Client
	documents         map[string]*vcclient.AddPIDRequest
	credentialType    string
	exampleCredential []map[string]any
	exampleFilePaths  []string
}

func NewPIDUserClient(ctx context.Context, client *Client) (*pidUsersClient, error) {
	usersClient := &pidUsersClient{
		client:            client,
		documents:         map[string]*vcclient.AddPIDRequest{},
		exampleCredential: []map[string]any{},
		exampleFilePaths:  []string{},
		credentialType:    "pid_user",
	}

	return usersClient, nil
}

func (c *pidUsersClient) makeSourceData(sourceFilePath string) error {
	for pidNumber, id := range c.client.identities {

		doc := &vcclient.AddPIDRequest{
			Username: strings.ToLower(id.Identities[0].FamilyName),
			Password: strings.ToLower(id.Identities[0].FamilyName),
			Identity: &id.Identities[0],
			Meta: &model.MetaData{
				AuthenticSource: "PID_Provider:00001",
				DocumentType:    model.CredentialTypeUrnEudiPid1,
				DocumentVersion: "1.0.0",
				DocumentID:      fmt.Sprintf("pid_user_%s", pidNumber),
			},
		}

		c.documents[pidNumber] = doc

	}
	return nil
}

func (c *pidUsersClient) save2Disk() error {
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
