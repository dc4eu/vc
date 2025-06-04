package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/vcclient"

	"github.com/xuri/excelize/v2"
)

type clients interface {
	makeSourceData(sourceFilePath string) error
	save2Disk() error
}

type Client struct {
	cfg            *model.Cfg
	identities     map[string]*vcclient.UploadRequest
	vcClient       *vcclient.Client
	vcClientConfig *vcclient.Config
	log            *logger.Log

	pda1Client            clients
	ehicClient            clients
	pidClient             clients
	elmClient             clients
	diplomaClient         clients
	MicroCredentialClient clients
	UserClient            clients
}

func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	client := &Client{
		cfg:        cfg,
		identities: map[string]*vcclient.UploadRequest{},
		vcClientConfig: &vcclient.Config{
			URL: cfg.MockAS.DatastoreURL,
		},
		log: log.New("bootstrapper"),
	}

	var err error
	client.vcClient, err = vcclient.New(client.vcClientConfig)
	if err != nil {
		return nil, fmt.Errorf("new datastore client: %w", err)
	}

	client.pda1Client, err = NewPDA1Client(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new pda1 client: %w", err)
	}

	client.ehicClient, err = NewEHICClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new ehic client: %w", err)
	}

	client.pidClient, err = NewPIDClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new pid client: %w", err)
	}

	client.elmClient, err = NewELMClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new elm client: %w", err)
	}

	client.diplomaClient, err = NewDiplomaClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new diploma client: %w", err)
	}

	client.MicroCredentialClient, err = NewMicroCredentialClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new micro credential client: %w", err)
	}

	client.UserClient, err = NewUserClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new user client: %w", err)
	}

	for _, credentialType := range []string{"ehic", "pda1", "pid", "elm", "diploma", "microcredential"} { // pid is not working
		jsonPath := filepath.Join("../../../bootstrapping", fmt.Sprintf("%s.json", credentialType))
		if err := client.uploader(ctx, jsonPath); err != nil {
			return nil, fmt.Errorf("uploader: %w", err)
		}
	}

	for _, credentialType := range []string{"user"} {
		jsonPath := filepath.Join("../../../bootstrapping", fmt.Sprintf("%s.json", credentialType))
		if err := client.userUpload(ctx, jsonPath); err != nil {
			return nil, fmt.Errorf("user upload: %w", err)
		}
	}

	return client, nil
}

func (c *Client) makeIdentities(sourceFilePath string) error {
	fs, err := excelize.OpenFile(sourceFilePath)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer func() {
		// Close the spreadsheet.
		if err := fs.Close(); err != nil {
			fmt.Println(err)
		}
	}()

	// Get value from cell by given worksheet name and cell reference.
	pidRows, err := fs.GetRows("PID")
	if err != nil {
		panic(err)
	}

	for _, row := range pidRows {
		if row[0] == "" || row[0] == "pid_id" {
			continue
		}
		dateOfBirth := strings.ReplaceAll(row[8], "/", "-")
		c.identities[row[0]] = &vcclient.UploadRequest{
			DocumentDataVersion: "1.0.0",
			Identities: []model.Identity{
				{
					AuthenticSourcePersonID: fmt.Sprintf("authentic_source_person_id_%s", row[0]),
					Schema: &model.IdentitySchema{
						Name:    "DefaultSchema",
						Version: "",
					},
					FamilyName:       row[6],
					GivenName:        row[7],
					BirthDate:        dateOfBirth,
					BirthPlace:       "Tulegatan 11",
					Nationality:      []string{"SE"},
					ExpiryDate:       "2033-01-01",
					IssuingAuthority: "SUNET",
					IssuingCountry:   "SE",
				},
			},
		}

	}

	return nil
}

func (c *Client) uploader(ctx context.Context, jsonPath string) error {
	b, err := os.ReadFile(jsonPath)
	if err != nil {
		return err
	}

	bodys := map[string]*vcclient.UploadRequest{}
	if err := json.Unmarshal(b, &bodys); err != nil {
		return err
	}

	for _, body := range bodys {
		resp, err := c.vcClient.Root.Upload(ctx, body)
		if err != nil {
			c.log.Error(err, "Upload", "resp", resp)
			return err
		}

		c.log.Debug("Upload", "resp", resp.StatusCode)
	}

	return nil
}

func (c *Client) userUpload(ctx context.Context, jsonPath string) error {
	b, err := os.ReadFile(jsonPath)
	if err != nil {
		return err
	}

	bodys := map[string]*vcclient.AddPIDRequest{}
	if err := json.Unmarshal(b, &bodys); err != nil {
		return err
	}

	for _, body := range bodys {
		resp, err := c.vcClient.User.AddPID(ctx, body)
		if err != nil {
			c.log.Error(err, "User Upload", "resp", resp)
			return err
		}
		c.log.Debug("User Upload", "resp", resp.StatusCode)
	}

	return nil
}
