package bootstrapper

import "vc/pkg/model"

type elmClient struct {
	client         *Client
	documents      map[string]*model.CompleteDocument
	credentialType string
}

func NewELMClient(client *Client) (*elmClient, error) {
	elmClient := &elmClient{
		client:         client,
		documents:      map[string]*model.CompleteDocument{},
		credentialType: "elm",
	}

	return elmClient, nil
}

func (c *elmClient) makeSourceData(sourceFilePath string) error {

	return nil
}
