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
		RevocationID:            gofakeit.UUID(),
		CollectID:               gofakeit.UUID(),
		QR: model.QR{
			Base64Image: "asdasdasd",
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
