package model

// Upload is a generic type for upload
type Upload struct {
	Meta         MetaData `json:"meta" bson:"meta" validate:"required"`
	DocumentData any      `json:"document_data" bson:"document_data"`
}

// MetaData is a generic type for metadata
type MetaData struct {
	AuthenticSource         string `json:"authentic_source,omitempty" bson:"authentic_source" validate:"required"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id,omitempty" bson:"authentic_source_person_id" validate:"required"`
	DocumentType            string `json:"document_type,omitempty" bson:"document_type" validate:"required,oneof=PDA1 EHIC"`
	DocumentID              string `json:"document_id,omitempty" bson:"document_id" validate:"required"`
	FirstName               string `json:"first_name,omitempty" bson:"first_name" validate:"required"`
	LastName                string `json:"last_name,omitempty" bson:"last_name" validate:"required"`
	DateOfBirth             string `json:"date_of_birth,omitempty" bson:"date_of_birth" validate:"required"`
	UID                     string `json:"uid,omitempty" bson:"uid" validate:"required"`
	RevocationID            string `json:"revocation_id,omitempty" bson:"revocation_id " validate:"required"`
	CollectID               string `json:"collect_id,omitempty" bson:"collect_id" validate:"required"`
	QR                      QR     `json:"qr,omitempty" bson:"qr" validate:"required"`
}

// QR is a collection of fields representing a QR code
type QR struct {
	Base64Image string `json:"base64_image" bson:"base64_image" validate:"required"`
}
