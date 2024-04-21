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
	FirstName               string `json:"first_name"`
	LastName                string `json:"last_name"`
	DateOfBirth             string `json:"date_of_birth"`
	CollectID               string `json:"collect_id"`
}

func (c *Client) mockOne(ctx context.Context, data MockInputData) (*model.Upload, error) {
	c.log.Debug("mockOne")
	person := gofakeit.Person()

	if data.AuthenticSourcePersonID == "" {
		data.AuthenticSourcePersonID = gofakeit.UUID()
	}

	if data.FirstName == "" {
		data.FirstName = person.FirstName
	}

	if data.LastName == "" {
		data.LastName = person.LastName
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
		AuthenticSource:         data.AuthenticSource,
		AuthenticSourcePersonID: data.AuthenticSourcePersonID,
		DocumentType:            data.DocumentType,
		DocumentID:              data.DocumentID,
		DocumentVersion:         "1.0.0",
		FirstName:               data.FirstName,
		LastName:                data.LastName,
		DateOfBirth:             data.DateOfBirth,
		CollectID:               data.CollectID,
		ValidFrom:               gofakeit.Date().Unix(),
		ValidTo:                 gofakeit.Date().Unix(),
		MemberState:             c.randomISO31661Alpha3EU(),
		Revocation: &model.Revocation{
			ID:                 gofakeit.UUID(),
			Revoked:            gofakeit.Bool(),
			FollowUpCredential: gofakeit.URL(),
			RevokedAt:          gofakeit.Date().Unix(),
			Reason:             gofakeit.RandomString([]string{"lost", "stolen", "expired"}),
		},
	}

	c.log.Debug("1")

	identity := &model.Identity{
		Version:    "1.0.0",
		FamilyName: person.LastName,
		GivenName:  person.FirstName,
		BirthDate:  gofakeit.Date().String(),
	}

	attestation := &model.Attestation{
		Version:          "1.0.0",
		Type:             data.DocumentType,
		DescriptionShort: "short",
		DescriptionLong:  "long",
		DescriptionStructured: map[string]any{
			"en": "issuer",
			"sv": "utfärdare",
		},
	}

	mockUpload := &model.Upload{
		Meta:        meta,
		Identity:    identity,
		Attestation: attestation,
	}

	switch data.DocumentType {
	case "PDA1":
		mockUpload.DocumentData = c.PDA1.random(ctx, person)
	case "EHIC":
		mockUpload.DocumentData = c.EHIC.random(ctx, person)
	default:
		return nil, model.ErrNoKnownDocumentType
	}

	c.log.Debug("2")
	if err := helpers.CheckSimple(mockUpload); err != nil {
		c.log.Debug("mockOne", "error", err)
		return nil, err
	}

	c.log.Debug("3")

	return mockUpload, nil
}
