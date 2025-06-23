package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"vc/pkg/vcclient"
)

type usersClient struct {
	client            *Client
	documents         map[string]*vcclient.AddPIDRequest
	credentialType    string
	exampleCredential []map[string]any
	exampleFilePaths  []string
}

func NewUserClient(ctx context.Context, client *Client) (*usersClient, error) {
	usersClient := &usersClient{
		client:            client,
		documents:         map[string]*vcclient.AddPIDRequest{},
		exampleCredential: []map[string]any{},
		exampleFilePaths:  []string{},
		credentialType:    "user",
	}

	return usersClient, nil
}

func (c *usersClient) makeSourceData(sourceFilePath string) error {
	for pidNumber, id := range c.client.identities {

		doc := &vcclient.AddPIDRequest{
			Username:        strings.ToLower(id.Identities[0].FamilyName),
			Password:        strings.ToLower(id.Identities[0].FamilyName),
			Identity:        &id.Identities[0],
			DocumentType:    "generic.pid",
			AuthenticSource: "generic.pid",
		}

		c.documents[pidNumber] = doc

	}
	return nil
}

func (c *usersClient) save2Disk() error {
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
