package model

import (
	"context"
	"encoding/base64"
	"net/url"

	"github.com/skip2/go-qrcode"
)

// Upload is a generic type for upload
type Upload struct {
	Meta         *MetaData    `json:"meta" bson:"meta" validate:"required"`
	Identity     *Identity    `json:"identity,omitempty" bson:"identity" validate:"required"`
	Attestation  *Attestation `json:"attestation,omitempty" bson:"attestation" validate:"required"`
	DocumentData any          `json:"document_data" bson:"document_data" validate:"required"`
	QR           *QR          `json:"qr" bson:"qr"`
}

// QRGenerator generates a QR code
func (u *Upload) QRGenerator(ctx context.Context, baseURL string, recoveryLevel, size int) error {
	deepLink, err := url.Parse(baseURL)
	if err != nil {
		return err
	}

	q := deepLink.Query()

	q.Add("member_state", u.Meta.MemberState)
	q.Add("document_type", u.Meta.DocumentType)
	q.Add("authentic_source", u.Meta.AuthenticSource)
	q.Add("document_id", u.Meta.DocumentID)

	deepLink.RawQuery = q.Encode()

	qrPNG, err := qrcode.Encode(deepLink.String(), qrcode.RecoveryLevel(recoveryLevel), size)
	if err != nil {
		return err
	}

	qrBase64 := base64.StdEncoding.EncodeToString(qrPNG)

	u.QR = &QR{
		DeepLink:      deepLink.String(),
		QRBase64Image: qrBase64,
	}

	return nil
}

// MetaData is a generic type for metadata
type MetaData struct {
	// required: true
	// example: SUNET
	AuthenticSource string `json:"authentic_source,omitempty" bson:"authentic_source" validate:"required"`

	// required: true
	// example: 65636cbc-c03f-11ee-8dc4-67135cc9bd8a
	AuthenticSourcePersonID string `json:"authentic_source_person_id,omitempty" bson:"authentic_source_person_id" validate:"required"`

	// required: true
	// example: 1
	DocumentVersion int `json:"document_version,omitempty" bson:"document_version" validate:"required,min=1"`

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

	// required: false
	// example: 8dbd2680-c03f-11ee-a21b-034aafe41222
	RevocationID string `json:"revocation_id,omitempty" bson:"revocation_id" validate:"required"`

	// required: false
	// example: 98fe67fc-c03f-11ee-bbee-4345224d414f
	CollectID string `json:"collect_id,omitempty" bson:"collect_id" validate:"required"`

	// required: true
	// example: "DE"
	MemberState string `json:"member_state,omitempty" bson:"member_state" validate:"required,iso3166_1_alpha2"`

	// TODO(masv): ISO8601?
	// required: true
	// example: 2024-01-01
	ValidFrom string `json:"valid_from,omitempty" bson:"valid_from" validate:"required"`

	// TODO(masv): ISO8601?
	// required: true
	// example: 2024-12-31
	ValidTo string `json:"valid_to,omitempty" bson:"valid_to" validate:"required"`

	// required: true
	// example: 2024-03-15T10:00:00Z+01:00
	IssuedAt string `json:"issued_at,omitempty" bson:"issued_at"`

	// required: true
	// example: 2024-03-15T10:00:00Z+01:00
	ExpiredAt string `json:"expired_at,omitempty" bson:"expired_at"`
}

// Identity identifies a person
type Identity struct {
	// required: true
	// example: 1.0.0
	Version string `json:"version,omitempty" bson:"version" validate:"required"`

	// required: true
	// example: Svensson
	FamilyName string `json:"family_name,omitempty" bson:"family_name" validate:"required"`

	// required: true
	// example: Magnus
	GivenName string `json:"given_name,omitempty" bson:"given_name" validate:"required"`

	// required: true
	// example: 1970-01-01
	BirthDate string `json:"birth_date,omitempty" bson:"birth_date" validate:"required"`

	// required: true
	// example: 85f90d4c-c03f-11ee-9386-ef1b105c4f3e
	UID string `json:"uid,omitempty" bson:"uid" validate:"required"`

	// required: false
	// example: Karlsson
	FamilyNameAtBirth string `json:"family_name_at_birth,omitempty" bson:"family_name_at_birth"`

	// required: false
	// example: Magnus
	GivenNameAtBirth string `json:"given_name_at_birth,omitempty" bson:"given_name_at_birth"`

	// required: false
	// example: Stockholm
	BirthPlace string `json:"birth_place,omitempty" bson:"birth_place"`

	// required: false
	// example: male
	Gender string `json:"gender,omitempty" bson:"gender"`

	// TODO(masv): int instead of string?
	// required: false
	// example: 19
	AgeOver18 string `json:"age_over_18,omitempty" bson:"age_over_18"`

	// TODO(masv): int instead of string? How is supposed to work, query NN?
	// required: false
	// example: 19
	AgeOverNN string `json:"age_over_nn,omitempty" bson:"age_over_nn"`

	// TODO(masv): int instead of string?
	// required: false
	// example: 19
	AgeInYears string `json:"age_in_years,omitempty" bson:"age_in_years"`
	// String age_birth_year o As in current PID namespace

	// TODO(masv): int instead of string?
	// required: false
	// example: 1970
	AgeBirthYear string `json:"age_birth_year,omitempty" bson:"age_birth_year"`

	// TODO(masv): full name or just country code?
	// required: false
	// example: sweden
	BirthCountry string `json:"birth_country,omitempty" bson:"birth_country"`

	// required: false
	// example: Stockholm
	BirthState string `json:"birth_state,omitempty" bson:"birth_state"`

	// required: false
	// example: Stockholm
	BirthCity string `json:"birth_city,omitempty" bson:"birth_city"`

	// required: false
	// example: 221b baker street
	ResidentAddress string `json:"resident_address,omitempty" bson:"resident_address"`

	// required: false
	// example: england
	ResidentCountry string `json:"resident_country,omitempty" bson:"resident_country"`

	// required: false
	// example: england
	ResidentState string `json:"resident_state,omitempty" bson:"resident_state"`

	// required: false
	// example: london
	ResidentCity string `json:"resident_city,omitempty" bson:"resident_city"`

	// required: false
	// example: W1U 6SG
	ResidentPostalCode string `json:"resident_postal_code,omitempty" bson:"resident_postal_code"`

	// required: false
	// example: baker street
	ResidentStreet string `json:"resident_street,omitempty" bson:"resident_street"`

	// required: false
	// example: 221b
	ResidentHouseNumber string `json:"resident_house_number,omitempty" bson:"resident_house_number"`

	// required: false
	// example: swedish
	Nationality string `json:"nationality,omitempty" bson:"nationality"`
}

// Attestation is a collection of fields representing an attestation
// TODO(masv): Change AttestationData to Attestation, data seems redundant
type Attestation struct {
	// TODO(masv): change AttestationDataVersion to AttestationVersion, data seems redundant
	// required: true
	// example: 1.0.0
	Version int `json:"version,omitempty" bson:"version" validate:"required"`

	// required: true
	// example: secure
	Type string `json:"type,omitempty" bson:"type" validate:"required"`

	// TODO(masv): ShortText to DescriptionShort, more descriptive, pun intended
	// required: true
	// example: EHIC
	DescriptionShort string `json:"description_short,omitempty" bson:"description_short" validate:"required"`

	// TODO(masv): change TextLong to DescriptionLong
	// required: true
	// example: European Health Insurance Card
	DescriptionLong string `json:"description_long,omitempty" bson:"description_long" validate:"required"`

	// required: true
	// example: {"description": "a key-value pair", "key": "value"}
	StructuredInformation map[string]any `json:"structured_information,omitempty" bson:"structured_information" validate:"required"`
}

// QR is a collection of fields representing a QR code
type QR struct {
	QRBase64Image string `json:"base64_image" bson:"base64_image" validate:"required"`
	DeepLink      string `json:"deep_link" bson:"deep_link" validate:"required"`
}
