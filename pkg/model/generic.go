package model

import (
	"encoding/json"
	"vc/pkg/openid4vci"
)

// CompleteDocument is a generic type for upload
type CompleteDocument struct {
	Meta            *MetaData        `json:"meta,omitempty" bson:"meta" validate:"required"`
	Identities      []Identity       `json:"identities,omitempty" bson:"identities" validate:"required"`
	DocumentDisplay *DocumentDisplay `json:"document_display,omitempty" bson:"document_display" validate:"required"`
	DocumentData    map[string]any   `json:"document_data,omitempty" bson:"document_data" validate:"required"`

	// required: true
	// example: "1.0.0"
	DocumentDataVersion string         `json:"document_data_version,omitempty" bson:"document_data_version" validate:"required,semver"`
	QR                  *openid4vci.QR `json:"qr,omitempty" bson:"qr"`
}

// CompleteDocuments is a array of CompleteDocument
type CompleteDocuments []CompleteDocument

// DocumentList is a generic type for document list
type DocumentList struct {
	Meta            *MetaData        `json:"meta,omitempty" bson:"meta" validate:"required"`
	DocumentDisplay *DocumentDisplay `json:"document_display,omitempty" bson:"document_display"`
	QR              *openid4vci.QR   `json:"qr,omitempty" bson:"qr" validate:"required"`
}

// Document is a generic type for get document
type Document struct {
	Meta         *MetaData `json:"meta,omitempty" bson:"meta" validate:"required"`
	DocumentData any       `json:"document_data" bson:"document_data" validate:"required"`
}

// IDMapping is a generic type for ID mapping
type IDMapping struct {
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
}

// CredentialOffer https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html 4.1.1 Credential Offer Parameters
type CredentialOffer struct {
	CredentialIssuer           string                       `json:"credential_issuer"`
	CredentialConfigurationIDs []string                     `json:"credential_configuration_ids"`
	Grants                     map[string]map[string]string `json:"grants"`
}

// Marshal marshals the CredentialOffer
func (c *CredentialOfferConfig) Marshal() ([]byte, error) {
	return json.Marshal(c)
}

// Consent is a generic type for consent
type Consent struct {
	// required: true
	// example: "Using my data for research"
	ConsentTo string `json:"consent_to,omitempty" bson:"consent_to" validate:"required"`

	// required: true
	// example: "sess-123"
	SessionID string `json:"session_id,omitempty" bson:"session_id" validate:"required"`

	// required: true
	// example: 509567558
	// format: int64
	CreatedAt int64 `json:"created_at,omitempty" bson:"created_at" validate:"required"`
}

// Collect is a generic type for collect
type Collect struct {
	// required: false
	// example: 98fe67fc-c03f-11ee-bbee-4345224d414f
	ID string `json:"id,omitempty" bson:"id"`

	// required: false
	// example: 509567558
	// format: int64
	ValidUntil int64 `json:"valid_until,omitempty" bson:"valid_until"`
}

// MetaData is a generic type for metadata
type MetaData struct {
	// required: true
	// example: SUNET
	AuthenticSource string `json:"authentic_source,omitempty" bson:"authentic_source" validate:"required"`

	// required: true
	// example: "1.0.0"
	DocumentVersion string `json:"document_version,omitempty" bson:"document_version" validate:"required,semver"`

	// required: true
	// example: PDA1
	DocumentType string `json:"document_type,omitempty" bson:"document_type" validate:"required,oneof=urn:eudi:elm:1 urn:eudi:diploma:1 urn:eudi:micro_credential:1 urn:eudi:pid:1 urn:eudi:ehic:1 urn:eudi:pda1:1"`

	// required: true
	// example: 5e7a981c-c03f-11ee-b116-9b12c59362b9
	DocumentID string `json:"document_id,omitempty" bson:"document_id" validate:"required"`

	// RealData is a flag to indicate if the document contains real data
	// required: true
	// example: true
	RealData bool `json:"real_data" bson:"real_data"`

	Collect *Collect `json:"collect,omitempty" bson:"collect"`

	// Revocation is a collection of fields representing a revocation
	Revocation *Revocation `json:"revocation,omitempty" bson:"revocation"`

	// required: false
	// example: 509567558
	// format: int64
	CredentialValidFrom int64 `json:"credential_valid_from,omitempty" bson:"valid_from"`

	// required: false
	// example: 509567558
	// format: int64
	CredentialValidTo int64 `json:"credential_valid_to,omitempty" bson:"valid_to"`

	// required: false
	// example: file://path/to/schema.json or http://example.com/schema.json
	// format: string
	DocumentDataValidationRef string `json:"document_data_validation,omitempty" bson:"document_data_validation"`
}

// RevocationReference refer to a document
type RevocationReference struct {
	AuthenticSource string `json:"authentic_source,omitempty" bson:"authentic_source"`
	DocumentType    string `json:"document_type,omitempty" bson:"document_type"`
	DocumentID      string `json:"document_id,omitempty" bson:"document_id"`
}

// Revocation is a collection of fields representing a revocation
type Revocation struct {

	// ID is the ID of the revocation
	// required: false
	// example: 8dbd2680-c03f-11ee-a21b-034aafe41222
	ID string `json:"id,omitempty" bson:"id"`

	// Revoked is a flag to indicate if the document has been revoked
	// required: false
	// example: false
	Revoked bool `json:"revoked,omitempty" bson:"revoked"`

	Reference RevocationReference `json:"reference" bson:"reference"`

	// RevokedAt is the time the document was revoked or going to be revoked
	// required: false
	// example: 509567558
	// format: int64
	RevokedAt int64 `json:"revoked_at,omitempty" bson:"revoked_at"`

	// Reason is the reason for revocation
	// required: false
	// example: lost or stolen
	Reason string `json:"reason,omitempty" bson:"reason"`
}

// IdentitySchema is a collection of fields representing an identity schema
type IdentitySchema struct {
	// required: true
	// example: "SE"
	Name string `json:"name,omitempty" bson:"name" validate:"required"`

	// required: false
	// example: "1.0.0"
	Version string `json:"version,omitempty" bson:"version" validate:"omitempty,semver"`
}

// Identity identifies a person
type Identity struct {
	// required: true
	// example: 65636cbc-c03f-11ee-8dc4-67135cc9bd8a
	AuthenticSourcePersonID string `json:"authentic_source_person_id,omitempty" bson:"authentic_source_person_id"`

	Schema *IdentitySchema `json:"schema,omitempty" bson:"schema" validate:"required"`

	// required: true
	// example: Svensson
	FamilyName string `json:"family_name,omitempty" bson:"family_name" validate:"required,min=1,max=100"`

	// required: true
	// example: Magnus
	GivenName string `json:"given_name,omitempty" bson:"given_name" validate:"required,min=1,max=100"`

	// required: true
	// example: 1970-01-01 TODO: Day, month, and year?
	BirthDate string `json:"birth_date,omitempty" bson:"birth_date" validate:"required,datetime=2006-01-02"`

	// required: true
	// example: Stockholm
	BirthPlace string `json:"birth_place,omitempty" bson:"birth_place" validate:"omitempty,min=2,max=100"`

	// required: true
	// example: SE
	Nationality []string `json:"nationality,omitempty" bson:"nationality" validate:"omitempty,dive,iso3166_1_alpha2"`

	// required: false
	// example: <personnummer>
	PersonalAdministrativeNumber string `json:"personal_administrative_number,omitempty" bson:"personal_administrative_number" validate:"omitempty,min=4,max=50"`

	// required: false
	// example: facial image compliant with ISO 19794-5 or ISO 39794 specifications
	Picture string `json:"picture,omitempty" bson:"picture"`

	BirthFamilyName string `json:"birth_family_name,omitempty" bson:"birth_family_name" validate:"omitempty,min=1,max=100"`

	BirthGivenName string `json:"birth_given_name,omitempty" bson:"birth_given_name" validate:"omitempty,min=1,max=100"`

	// required: false
	// example: 0 = not known, 1 = male, 2 = female, ...
	Sex string `json:"sex,omitempty" bson:"sex" validate:"omitempty,oneof=0 1 2 3 4 5 6 7 8 9"`

	// required: false
	// example: <email-address>
	EmailAddress string `json:"email_address,omitempty" bson:"email_address" validate:"omitempty,email"`

	// required: false
	// example: <+mobile-phone-number>
	MobilePhoneNumber string `json:"mobile_phone_number,omitempty" bson:"mobile_phone_number" validate:"omitempty,e164"`

	// required: false
	// example: 221b Baker street
	ResidentAddress string `json:"resident_address,omitempty" bson:"resident_address"`

	// required: false
	// example: Baker street
	ResidentStreetAddress string `json:"resident_street_address,omitempty" bson:"resident_street_address" validate:"omitempty,min=1,max=100"`

	// required: false
	// example: 221b
	ResidentHouseNumber string `json:"resident_house_number,omitempty" bson:"resident_house_number"`

	// required: false
	// example: W1U 6SG
	ResidentPostalCode string `json:"resident_postal_code,omitempty" bson:"resident_postal_code"`

	// required: false
	// example: London
	ResidentCity string `json:"resident_city,omitempty" bson:"resident_city"`
	// required: false
	// example: england
	ResidentState string `json:"resident_state,omitempty" bson:"resident_state"`
	// required: false
	// example: England
	ResidentCountry string `json:"resident_country,omitempty" bson:"resident_country" validate:"omitempty,iso3166_1_alpha2"`

	AgeOver14 string `json:"age_over_14,omitempty" bson:"age_over_14"`

	AgeOver16 bool `json:"age_over_16,omitempty" bson:"age_over_16"`

	AgeOver18 bool `json:"age_over_18,omitempty" bson:"age_over_18"`

	AgeOver21 bool `json:"age_over_21,omitempty" bson:"age_over_21"`

	AgeOver65 bool `json:"age_over_65,omitempty" bson:"age_over_65"`

	AgeInYears int `json:"age_in_years,omitempty" bson:"age_in_years"`

	AgeBirthYear int `json:"age_birth_year,omitempty" bson:"age_birth_year"`

	// required: true
	// example:
	IssuingAuthority string `json:"issuing_authority,omitempty" bson:"issuing_authority"`
	// required: true
	// example:
	IssuingCountry string `json:"issuing_country,omitempty" bson:"issuing_country" validate:"omitempty,iso3166_1_alpha2"`

	// required: true
	// example: Date (and if possible time)
	ExpiryDate string `json:"expiry_date,omitempty" bson:"expiry_date" validate:"omitempty,datetime=2006-01-02"`

	IssuanceDate string `json:"issuance_date,omitempty" bson:"issuance_date"`

	// required: false
	// example:
	DocumentNumber string `json:"document_number,omitempty" bson:"document_number"`

	// required: false
	// example:
	IssuingJurisdiction string `json:"issuing_jurisdiction,omitempty" bson:"issuing_jurisdiction"`

	TrustAnchor string `json:"trust_anchor,omitempty" bson:"trust_anchor"`
}

// Marshal marshals the document to a map
func (i *Identity) Marshal() (map[string]any, error) {
	data, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}

	var doc map[string]any
	err = json.Unmarshal(data, &doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

// DocumentDisplay is a collection of fields representing display of document
type DocumentDisplay struct {
	// required: true
	// example: "1.0.0"
	Version string `json:"version,omitempty" bson:"version" validate:"required,semver"`

	// required: true
	// example: secure
	Type string `json:"type,omitempty" bson:"type" validate:"required"`

	// DescriptionStructured is a map of structured descriptions
	// required: true
	// example: {"en": "European Health Insurance Card", "sv": "Europeiskt sjukförsäkringskortet"}
	DescriptionStructured map[string]any `json:"description_structured,omitempty" bson:"description_structured" validate:"required"`
}

// SearchDocumentsReply the reply from search documents
type SearchDocumentsReply struct {
	Documents      []*CompleteDocument `json:"documents"`
	HasMoreResults bool                `json:"has_more_results"`
}

// SearchDocumentsRequest the request to search for documents
type SearchDocumentsRequest struct {
	AuthenticSource string `json:"authentic_source,omitempty"`
	DocumentType    string `json:"document_type,omitempty"`
	DocumentID      string `json:"document_id,omitempty"`
	CollectID       string `json:"collect_id,omitempty"`

	AuthenticSourcePersonID string `json:"authentic_source_person_id,omitempty"`

	FamilyName string `json:"family_name,omitempty"`
	GivenName  string `json:"given_name,omitempty"`
	BirthDate  string `json:"birth_date,omitempty"`
	BirthPlace string `json:"birth_place,omitempty"`

	Limit      int64          `json:"limit,omitempty"`
	Fields     []string       `json:"fields,omitempty"`
	SortFields map[string]int `json:"sort_fields,omitempty"`
}
