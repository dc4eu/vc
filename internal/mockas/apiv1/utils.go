package apiv1

import (
	"context"
	"vc/pkg/helpers"
	"vc/pkg/model"

	"github.com/brianvoe/gofakeit/v6"
)

func (c *Client) mockOne(ctx context.Context, authenticSourcePersonID, authenticSource, documentType string) (*model.Upload, error) {
	c.log.Debug("mockOne")
	person := gofakeit.Person()

	if authenticSourcePersonID == "" {
		authenticSourcePersonID = gofakeit.UUID()
	}

	meta := &model.MetaData{
		AuthenticSource:         authenticSource,
		AuthenticSourcePersonID: authenticSourcePersonID,
		DocumentType:            documentType,
		DocumentID:              gofakeit.UUID(),
		DocumentVersion:         "1.0.0",
		FirstName:               person.FirstName,
		LastName:                person.LastName,
		DateOfBirth:             gofakeit.Date().String(),
		CollectID:               gofakeit.UUID(),
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
		Type:             documentType,
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

	switch documentType {
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
