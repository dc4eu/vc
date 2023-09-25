package model

import (
	"time"
	"vc/pkg/ehic"
	"vc/pkg/pda1"
	"vc/pkg/testv1"
)

// GenericUpload is a generic type for upload
type GenericUpload struct {
	Attributes *GenericAttributes `json:"attributes" bson:"attributes" validate:"required"`
	Revoke     *Revoke            `json:"revoke,omitempty" bson:"revoke"`
	Collect    *Collect           `json:"collect,omitempty" bson:"collect"`
	Document   *GenericDocument   `json:"document" bson:"document" validate:"required"`
}

// GenericDocument is a generic type for document
type GenericDocument struct {
	PDA1   *pda1.Document   `json:"pda1,omitempty" bson:"pda1,omitempty" validate:"required_without=EHIC"`
	EHIC   *ehic.Document   `json:"ehic,omitempty" bson:"ehic,omitempty" validate:"required_without=PDA1"`
	Testv1 *testv1.Document `json:"testv1,omitempty" bson:"testv1,omitempty" validate:"required_without=PDA1,EHIC"`
}

// Revoke is a generic type for revocation
type Revoke struct {
	Token string    `json:"token" bson:"token"`
	TS    time.Time `json:"ts" bson:"ts"`
}

// Collect is a generic type for collect
type Collect struct {
	Token        string    `json:"token" bson:"token"`
	ValidUntilTS time.Time `json:"valid_until_ts" bson:"valid_until_ts"`
	UsedTS       time.Time `json:"used_ts" bson:"used_ts"`
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
