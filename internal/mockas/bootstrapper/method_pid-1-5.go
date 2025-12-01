package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"vc/pkg/model"
	"vc/pkg/vcclient"

	"github.com/brianvoe/gofakeit/v7"
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
		credentialType: "pid-1-5",
	}

	return pidClient, nil
}

func (c *pidClient) readPidUserFile(sourceFilePath string) error {
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

func (c *pidClient) makeSourceData(sourceFilePath string) error {
	if err := c.readPidUserFile(sourceFilePath); err != nil {
		return fmt.Errorf("read pid user file: %w", err)
	}

	for pidNumber, id := range c.pidUsers {
		c.documents[pidNumber] = &vcclient.UploadRequest{}

		// Parse birthdate to calculate age-related fields
		birthDate, _ := time.Parse("2006-01-02", id.Identity.BirthDate)
		now := time.Now()
		age := now.Year() - birthDate.Year()
		if now.YearDay() < birthDate.YearDay() {
			age--
		}

		c.documents[pidNumber].DocumentData = map[string]any{
			"given_name":                     id.Identity.GivenName,
			"family_name":                    id.Identity.FamilyName,
			"birthdate":                      id.Identity.BirthDate,
			"birth_place":                    gofakeit.City(),
			"age_birth_year":                 birthDate.Year(),
			"age_in_years":                   age,
			"age_over_14":                    age >= 14,
			"age_over_16":                    age >= 16,
			"age_over_18":                    age >= 18,
			"age_over_21":                    age >= 21,
			"age_over_65":                    age >= 65,
			"birth_family_name":              gofakeit.LastName(),
			"birth_given_name":               gofakeit.FirstName(),
			"sex":                            strconv.Itoa(gofakeit.RandomInt([]int{0, 1, 2, 9})),
			"nationality":                    gofakeit.CountryAbr(),
			"issuing_country":                id.Identity.IssuingCountry,
			"issuing_authority":              gofakeit.Company(),
			"issuing_jurisdiction":           gofakeit.State(),
			"document_number":                gofakeit.UUID(),
			"personal_administrative_number": gofakeit.SSN(),
			"issuance_date":                  gofakeit.Date().Format("2006-01-02"),
			"expiry_date":                    gofakeit.FutureDate().Format("2006-01-02"),
			"picture":                        "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76LAAAAFElEQVQYV2P8z8DwHwYGBgZGMAEADigBCCGZkB0AAAAASUVORK5CYII=",
			"email_address":                  gofakeit.Email(),
			"mobile_phone_number":            gofakeit.Phone(),
			"resident_address":               fmt.Sprintf("%s, %s %s", gofakeit.Street(), gofakeit.City(), gofakeit.Zip()),
			"resident_street_address":        gofakeit.Street(),
			"resident_house_number":          gofakeit.StreetNumber(),
			"resident_postal_code":           gofakeit.Zip(),
			"resident_city":                  gofakeit.City(),
			"resident_state":                 gofakeit.State(),
			"resident_country":               gofakeit.CountryAbr(),
			"authentic_source_person_id":     gofakeit.UUID(),
			"trust_anchor":                   "https://" + gofakeit.DomainName(),
			"arf":                            "1.5",
		}

		c.documents[pidNumber].Meta = &model.MetaData{
			AuthenticSource: "PID_Provider:00001",
			DocumentVersion: "1.0.0",
			VCT:             model.CredentialTypeUrnEudiPidARF151,
			Scope:           "pid_1_5",
			DocumentID:      fmt.Sprintf("document_id_pid_arf_1_5_%s", pidNumber),
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

func (c *pidClient) save2Disk() error {
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
