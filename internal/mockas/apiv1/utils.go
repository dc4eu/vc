package apiv1

import (
	"context"
	"vc/pkg/model"

	"github.com/brianvoe/gofakeit/v6"
)

func (c *Client) mockOne(ctx context.Context, authenticSource, documentType string) (*model.Upload, error) {
	person := gofakeit.Person()

	meta := &model.MetaData{
		AuthenticSource:         authenticSource,
		AuthenticSourcePersonID: gofakeit.UUID(),
		DocumentType:            documentType,
		DocumentID:              gofakeit.UUID(),
		FirstName:               person.FirstName,
		LastName:                person.LastName,
		DateOfBirth:             gofakeit.Date().String(),
		UID:                     gofakeit.UUID(),
		CollectID:               gofakeit.UUID(),
		Revoke: &model.Revoke{
			ID:                 gofakeit.UUID(),
			Revoked:            gofakeit.Bool(),
			FollowUpCredential: gofakeit.URL(),
			RevokedAt:          gofakeit.FutureDate(),
			Reason:             gofakeit.RandomString([]string{"lost", "stolen", "expired"}),
		},
	}
	mockUpload := &model.Upload{
		Meta: meta,
	}

	switch documentType {
	case "PDA1":
		mockUpload.DocumentData = c.PDA1.random(ctx, meta)
	case "EHIC":
		mockUpload.DocumentData = c.EHIC.random(ctx, meta)
	default:
		return nil, model.ErrNoKnownDocumentType
	}

	return mockUpload, nil
}
