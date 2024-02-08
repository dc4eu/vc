package model

// Upload is a generic type for upload
type Upload struct {
	Meta         *MetaData `json:"meta" bson:"meta" validate:"required"`
	DocumentData any       `json:"document_data" bson:"document_data"`
}

// MetaData is a generic type for metadata
type MetaData struct {
	// required: true
	// example: Sunet
	AuthenticSource string `json:"authentic_source,omitempty" bson:"authentic_source" validate:"required"`

	// required: true
	// example: 65636cbc-c03f-11ee-8dc4-67135cc9bd8a
	AuthenticSourcePersonID string `json:"authentic_source_person_id,omitempty" bson:"authentic_source_person_id" validate:"required"`

	// required: true
	// example: PDA1
	DocumentType string `json:"document_type,omitempty" bson:"document_type" validate:"required,oneof=PDA1 EHIC"`

	// required: true
	// example: 5e7a981c-c03f-11ee-b116-9b12c59362b9
	DocumentID string `json:"document_id,omitempty" bson:"document_id" validate:"required"`

	// required: true
	// example: John
	FirstName string `json:"first_name,omitempty" bson:"first_name" validate:"required"`

	// required: true
	// example: Doe
	LastName string `json:"last_name,omitempty" bson:"last_name" validate:"required"`

	// required: true
	// example: 1970-01-01
	DateOfBirth string `json:"date_of_birth,omitempty" bson:"date_of_birth" validate:"required"`

	// required: true
	// example: 85f90d4c-c03f-11ee-9386-ef1b105c4f3e
	UID string `json:"uid,omitempty" bson:"uid" validate:"required"`

	// required: true
	// example: 8dbd2680-c03f-11ee-a21b-034aafe41222
	RevocationID string `json:"revocation_id,omitempty" bson:"revocation_id " validate:"required"`

	// required: true
	// example: 98fe67fc-c03f-11ee-bbee-4345224d414f
	CollectID string `json:"collect_id,omitempty" bson:"collect_id" validate:"required"`

	// required: false
	QR QR `json:"qr,omitempty" bson:"qr"`
}

// QR is a collection of fields representing a QR code
type QR struct {
	Base64Image string `json:"base64_image" bson:"base64_image" validate:"required"`
}
