package model

import (
	"encoding/json"
	"vc/pkg/helpers"
	"vc/pkg/logger"
)

// GenericUpload is a generic type for upload
type GenericUpload struct {
	GenericAttributes
	Document any `json:"document" bson:"document"`
}

// GenericAttributes is the generic attributes
type GenericAttributes struct {
	DocumentType            string `json:"document_type" bson:"document_type" validate:"required,oneof=PDA1 EHIC"`
	DocumentID              string `json:"document_id" bson:"document_id" validate:"required"`
	AuthenticSource         string `json:"authentic_source" bson:"authentic_source" validate:"required"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id" bson:"authentic_source_person_id" validate:"required"`
	RevocationID            string `json:"revocation_id" bson:"revocation_id " validate:"required"`

	FirstName   string `json:"first_name" bson:"first_name" validate:"required"`
	LastName    string `json:"last_name" bson:"last_name" validate:"required"`
	DateOfBirth string `json:"date_of_birth" bson:"date_of_birth" validate:"required"`

	UID              string `json:"uid" bson:"uid" validate:"required"`
	LastNameAtBirth  string `json:"last_name_at_birth" bson:"last_name_at_birth"`
	FirstNameAtBirth string `json:"first_name_at_birth" bson:"first_name_at_birth"`
	PlaceOfBirth     string `json:"place_of_birth" bson:"place_of_birth"`
	CurrentAddress   string `json:"current_address" bson:"current_address"`
	Gender           string `json:"gender" bson:"gender"`
}

func castDocumentToStruct(in, out any, log *logger.Log) error {
	b, err := json.Marshal(in)
	if err != nil {
		log.Info("cant marshal document")
		return err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		log.Info("cant unmarshal document")
		return err
	}
	return nil
}

// Validate validates the generic upload
func (g *GenericUpload) Validate(log *logger.Log) error {
	switch g.DocumentType {
	case "PDA1":
		l := log.New("PDA1")
		v := &PDA1{}
		//	vv, ok := g.Document.(PDA1)
		//	if !ok {
		//		return ErrInvalidDocumentType
		//	}

		if err := castDocumentToStruct(g.Document, v, l); err != nil {
			return err
		}

		g.Document = v

		l.Info("cast", "document", g)
		return helpers.Check(g, l)
	case "EHIC":
		g.Document = g.Document.(*EHIC)
		return helpers.Check(g, log.New("EHIC"))
	default:
		return ErrInvalidDocumentType
	}
}
