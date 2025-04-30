package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"vc/pkg/datastoreclient"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/xuri/excelize/v2"
)

type clients interface {
	makeSourceData(sourceFilePath string) error
	save2Disk() error
}

type Client struct {
	cfg                   *model.Cfg
	identities            map[string]*model.CompleteDocument
	datastoreClient       *datastoreclient.Client
	datastoreClientConfig *datastoreclient.Config
	log                   *logger.Log

	pda1Client clients
	ehicClient clients
	pidClient  clients
}

func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	client := &Client{
		cfg:        cfg,
		identities: map[string]*model.CompleteDocument{},
		datastoreClientConfig: &datastoreclient.Config{
			URL: cfg.MockAS.DatastoreURL,
		},
		log: log.New("bootstrapper"),
	}

	var err error
	client.datastoreClient, err = datastoreclient.New(client.datastoreClientConfig)
	if err != nil {
		return nil, fmt.Errorf("new datastore client: %w", err)
	}

	//	client.makeIdentities("testdata/users_paris.xlsx")

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

	client.uploader(ctx)

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
		c.identities[row[0]] = &model.CompleteDocument{
			DocumentDataVersion: "1.0.0",
			Identities: []model.Identity{
				{
					AuthenticSourcePersonID: fmt.Sprintf("authentic_source_person_id_%s", row[0]),
					Schema: &model.IdentitySchema{
						Name:    "DefaultSchema",
						Version: "",
					},
					FamilyName: row[6],
					GivenName:  row[7],
					BirthDate:  dateOfBirth,
				},
			},
		}

	}

	return nil
}

func (c *Client) uploader(ctx context.Context) error {
	b, err := os.ReadFile("../../../bootstrapper/ehic.json")
	if err != nil {
		return err
	}

	body := &datastoreclient.UploadRequest{}
	if err := json.Unmarshal(b, body); err != nil {
		return err
	}

	resp, err := c.datastoreClient.Root.Upload(ctx, body)
	if err != nil {
		return err
	}

	c.log.Debug("Upload", "resp", resp.StatusCode)

	return nil
}
