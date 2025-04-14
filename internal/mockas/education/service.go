package education

import (
	"context"
	"encoding/json"
	"os"
	"vc/pkg/datastoreclient"
	"vc/pkg/logger"
)

type Service struct {
	users           map[string][]users
	log             *logger.Log
	datastoreClient *datastoreclient.Client
}

type users struct {
	firstName          string
	lastName           string
	dateOfBirth        string
	number             string
	document_data_path string
}

func New(ctx context.Context, datastoreURL string, log *logger.Log) (*Service, error) {
	client := &Service{
		log: log,
		users: map[string][]users{
			"diploma": {
				{
					firstName:          "Helen",
					lastName:           "Mirren",
					dateOfBirth:        "1996-01-30",
					number:             "100",
					document_data_path: "../../../standards/education_credential/diploma/HE-diploma-9ad88a95-2f9a-4a1d-9e08-a61e213a3eac-degreeHBO-M.xml.json",
				},
				{
					firstName:          "Gary",
					lastName:           "Oldman",
					dateOfBirth:        "1988-09-09",
					number:             "102",
					document_data_path: "../../../standards/education_credential/diploma/HE-diploma-d1f071a2-7999-4950-910f-8edbebdcd336-degreeandcourses_Multi-Diploma.xml.json",
				},
				{
					firstName:          "Brad",
					lastName:           "Pitt",
					dateOfBirth:        "1974-12-07",
					number:             "106",
					document_data_path: "../../../standards/education_credential/diploma/HE-diploma-fb6b7ba8-27c6-400a-9bd3-7cb1fed4ccd9-degreeMBO.xml.json",
				},
			},
			"microcredential": {
				{
					firstName:          "Helen",
					lastName:           "Mirren",
					dateOfBirth:        "1996-01-30",
					number:             "100",
					document_data_path: "../../../standards/education_credential/micro_credential/mbob_eo_eov_microcredential_full.json",
				},
			},
		},
	}

	var err error
	client.datastoreClient, err = datastoreclient.New(&datastoreclient.Config{
		URL: datastoreURL,
	})
	if err != nil {
		return nil, err
	}

	resp, err := client.apply(ctx)
	if err != nil {
		client.log.Debug("apply error", "error", err, "http resp", resp)
		return nil, err
	}

	return client, nil
}

func (c *Service) readDocumentDataFile(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	data := map[string]any{}
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, err
	}

	return data, nil
}

func (s *Service) Close(ctx context.Context) error {
	return nil
}
