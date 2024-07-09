package apiv1

import (
	"context"
	"vc/pkg/helpers"
	"vc/pkg/model"

	"github.com/brianvoe/gofakeit/v6"
)

// MockInputData is the input data for the mock function
type MockInputData struct {
	DocumentType            string `json:"document_type"`
	DocumentID              string `json:"document_id"`
	AuthenticSource         string `json:"authentic_source"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
	GivenName               string `json:"given_name"`
	FamilyName              string `json:"family_name"`
	DateOfBirth             string `json:"date_of_birth"`
	CollectID               string `json:"collect_id"`
}

func (c *Client) mockOne(ctx context.Context, data MockInputData) (*model.UploadDocument, error) {
	c.log.Debug("mockOne")
	person := gofakeit.Person()

	if data.AuthenticSourcePersonID == "" {
		data.AuthenticSourcePersonID = gofakeit.UUID()
	}

	if data.GivenName == "" {
		data.GivenName = person.FirstName
	}

	if data.FamilyName == "" {
		data.FamilyName = person.LastName
	}

	if data.DateOfBirth == "" {
		data.DateOfBirth = gofakeit.Date().String()
	}

	if data.CollectID == "" {
		data.CollectID = gofakeit.UUID()
	}
	if data.DocumentID == "" {
		data.DocumentID = gofakeit.UUID()
	}

	meta := &model.MetaData{
		AuthenticSource: data.AuthenticSource,
		DocumentType:    data.DocumentType,
		DocumentID:      data.DocumentID,
		DocumentVersion: "1.0.0",
		RealData:        false,
		Collect: &model.Collect{
			ID:         data.CollectID,
			ValidUntil: 0,
		},
		CredentialValidFrom: gofakeit.Date().Unix(),
		CredentialValidTo:   gofakeit.Date().Unix(),
		Revocation: &model.Revocation{
			ID:      gofakeit.UUID(),
			Revoked: false,
			Reference: model.RevocationReference{
				AuthenticSource: data.AuthenticSource,
				DocumentType:    data.DocumentType,
				DocumentID:      data.DocumentID,
			},
			//Reason: gofakeit.RandomString([]string{"lost", "stolen", "expired"}),
		},
	}

	identity := &model.Identity{
		AuthenticSourcePersonID: data.AuthenticSourcePersonID,
		Schema: &model.IdentitySchema{
			Name:    "SE",
			Version: "1.0.2",
		},
		FamilyName: person.LastName,
		GivenName:  person.FirstName,
		BirthDate:  gofakeit.Date().String(),
	}

	documentDisplay := &model.DocumentDisplay{
		Version: "1.0.0",
		Type:    data.DocumentType,
		DescriptionStructured: map[string]any{
			"en": "issuer",
			"sv": "utfärdare",
		},
	}

	mockUpload := &model.UploadDocument{
		Meta:            meta,
		Identity:        identity,
		DocumentDisplay: documentDisplay,
	}

	switch data.DocumentType {
	case "PDA1":
		mockUpload.DocumentData = c.PDA1.random(ctx, person)
	case "EHIC":
		mockUpload.DocumentData = c.EHIC.random(ctx, person)
	default:
		return nil, model.ErrNoKnownDocumentType
	}

	mockUpload.DocumentDataVersion = "1.0.0"

	c.log.Debug("2")
	if err := helpers.CheckSimple(mockUpload); err != nil {
		c.log.Debug("mockOne", "error", err)
		return nil, err
	}

	c.log.Debug("3")

	return mockUpload, nil
}
