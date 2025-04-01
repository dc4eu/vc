package education

import (
	"encoding/json"
	"fmt"
	"strings"
)

func NewDiploma() *DiplomaDocument {
	doc := &DiplomaDocument{
		Type: []string{
			"VerifiableCredential",
			"EuropeanDigitalCredential",
		},
		CredentialProfiles: Fat{
			ID:   "http://data.europa.eu/snb/credential/e34929035b",
			Type: "Concept",
			InScheme: DiplomaInScheme{
				ID:   "http://data.europa.eu/snb/credential/25831c2",
				Type: "ConceptScheme",
			},
			PrefLabel: DiplomaPrefLabel{
				En: "Generic",
			},
		},

		CredentialSchema: Fat{
			ID:   "http://data.europa.eu/snb/model/ap/edc-generic-full",
			Type: "ShaclValidator2017",
		},
	}

	base64Image := "/9j/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/yQALCAABAAEBAREA/8wABgAQEAX/2gAIAQEAAD8A0s8g/9k="
	dateOfBirth := "1972-06-19T00:00:00"
	awardingDate := "2004-03-31T00:00:00"

	doc.AddDisplayParameter(base64Image, "JPEG")
	doc.AddCredentialSubject(dateOfBirth, awardingDate, "")

	return doc
}

type DiplomaDocument struct {
	Type               []string          `json:"type" validate:"required"`
	CredentialProfiles Fat               `json:"credentialProfiles"`
	DisplayParameter   *DisplayParameter `json:"displayParameter"`
	CredentialSchema   Fat               `json:"credentialSchema"`
	CredentialSubject  CredentialSubject `json:"credentialSubject"`
}

func (d *DiplomaDocument) AddCredentialSubject(dateOfBirth, awardingDate, noteLiteral string) {
	doc := CredentialSubject{
		ID:          "urn:epass:person:1335bfa5-3d8f-405c-8eb3-958e1becea8c",
		Type:        "Person",
		DateOfBirth: dateOfBirth,
		HasClaim: HasClaim{
			ID:   "urn:epass:learningAchievement:99ba5709-3174-4775-9845-d1e398246822",
			Type: "LearningAchievement",
			AwardedBy: AwardedBy{
				ID:   "urn:epass:awardingProcess:0317c922-1044-455f-8157-df4e85373a6b",
				Type: "AwardingProcess",
				AwardingBody: DiplomaAwardingBody{
					ID:   "urn:epass:org:069bb272-b0b4-4bf0-be25-063e18118455",
					Type: "Organisation",
					Location: DiplomaLocation{
						ID:   "urn:epass:location:fbc56047-6869-4a81-a14c-d6e1d3afc43c",
						Type: "Location",
						Address: DiplomaAddress{
							ID:   "urn:epass:address:53ac5e64-8ba2-4fa2-8abb-e1ef9a1562d9",
							Type: "Address",
							CountryCode: Fat{
								ID:   "http://publications.europa.eu/resource/authority/country/NLD",
								Type: "Concept",
								InScheme: DiplomaInScheme{
									ID:   "http://publications.europa.eu/resource/authority/country",
									Type: "ConceptScheme",
								},
								PrefLabel: DiplomaPrefLabel{
									En: "Netherlands",
								},
								Notation: "country",
							},
						},
					},
					Identifier: []Fat{
						{
							ID:         "urn:epass:identifier:eddc65e9-1e3e-4ff8-8eac-a3b1af2878d6",
							Type:       "Identifier",
							SchemaName: "schac",
							Notation:   "duo.nl",
						},
						{
							ID:         "urn:epass:identifier:0bcf2af5-ca54-4490-971c-31e9902c314f",
							Type:       "Identifier",
							SchemaName: "BRIN",
							Notation:   "27NF",
						},
					},
					LegalName: map[string]string{
						"nl": "ArtEZ",
					},
					Homepage: Fat{
						ID:         "urn:epass:webResource:1b4e6a8c-a362-40bc-9c63-1889b375cdf0",
						Type:       "WebResource",
						ContentURL: "https://duo.nl",
					},
				},
				AwardingDate: awardingDate,
				Used: DiplomaUsed{
					ID:   "converter:assessment:1",
					Type: "LearningAssessment",
					AssessedBy: DiplomaAssessedBy{
						ID:   "urn:epass:org:99a07d36-ae7c-4935-bea6-8fe122b2307d",
						Type: "Organisation",
						Location: DiplomaLocation{
							ID:   "urn:epass:location:c0716228-cdb7-4d81-8f91-23c5d675a901",
							Type: "Location",
							Address: DiplomaAddress{
								ID:   "urn:epass:address:40336b1e-e98e-4ad4-b852-f420160290e4",
								Type: "Address",
								CountryCode: Fat{
									ID:   "http://publications.europa.eu/resource/authority/country/NLD",
									Type: "Concept",
									InScheme: DiplomaInScheme{
										ID:   "http://publications.europa.eu/resource/authority/country",
										Type: "ConceptScheme",
									},
									PrefLabel: DiplomaPrefLabel{
										En: "Netherlands",
									},
									Notation: "country",
								},
							},
						},
						Identifier: []Fat{
							{
								ID:         "urn:epass:identifier:2cbfa317-f665-4107-b2dc-5949632ff388",
								Type:       "Identifier",
								SchemaName: "schac",
								Notation:   "duo.nl",
							},
							{
								ID:         "urn:epass:identifier:b993a38f-2b2a-4f05-bc49-8132aac97f71",
								Type:       "Identifier",
								SchemaName: "BRIN",
								Notation:   "27NF",
							},
						},
						LegalName: map[string]string{
							"nl": "ArtEZ",
						},
						Homepage: Fat{
							ID:         "urn:epass:webResource:23d14143-207b-4834-87f5-7b8568b8248f",
							Type:       "WebResource",
							ContentURL: "https://duo.nl",
						},
					},
				},
			},
			Grade: DiplomaGrade{},
		},
	}

	d.CredentialSubject = doc

}

type CredentialSubject struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	DateOfBirth string   `json:"dateOfBirth"`
	HasClaim    HasClaim `json:"hasClaim"`
}

type HasClaim struct {
	ID        string       `json:"id"`
	Type      string       `json:"type"`
	AwardedBy AwardedBy    `json:"awardedBy"`
	Grade     DiplomaGrade `json:"grade"`
}

type DiplomaGrade struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	NoteFormat  DiplomaNoteFormat `json:"noteFormat"`
	NoteLiteral string            `json:"noteLiteral"`
}

type DiplomaNoteFormat struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Definition DiplomaDefinition `json:"definition"`
}

type DiplomaDefinition struct {
	UND string `json:"UND"`
}

type AwardedBy struct {
	ID           string              `json:"id"`
	Type         string              `json:"type"`
	AwardingBody DiplomaAwardingBody `json:"awardingBody"`
	AwardingDate string              `json:"awardingDate"`
	Used         DiplomaUsed         `json:"used"`
}

type DiplomaAwardingBody struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Location   DiplomaLocation   `json:"location"`
	Identifier []Fat             `json:"identifier"`
	LegalName  map[string]string `json:"legalName"`
	Homepage   Fat               `json:"homepage"`
}

type DiplomaLocation struct {
	ID      string         `json:"id"`
	Type    string         `json:"type"`
	Address DiplomaAddress `json:"address"`
}

type DiplomaAddress struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	CountryCode Fat    `json:"countryCode"`
}

type DiplomaUsed struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	AssessedBy DiplomaAssessedBy `json:"assessedBy"`
}

type DiplomaAssessedBy struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Location   DiplomaLocation   `json:"location"`
	Identifier []Fat             `json:"identifier"`
	LegalName  map[string]string `json:"legalName"`
	Homepage   Fat               `json:"homepage"`
}

func (d *DiplomaDocument) AddDisplayParameter(base64Image, imageContentType string) {
	d.DisplayParameter = &DisplayParameter{
		ID:   "urn:epass:displayParameter:1",
		Type: "DisplayParameter",
		IndividualDisplay: DiplomaIndividualDisplay{
			ID:   "urn:epass:individualDisplay:a0a3d808-96d6-4b97-95e6-256abf948ff1",
			Type: "IndividualDisplay",
			DisplayDetail: DisplayDetail{
				ID:   "urn:epass:displayDetail:cbb965c7-a71b-464e-865b-faf2130e40d4",
				Type: "DisplayDetail",
				Image: MediaObject{
					ID:      "urn:epass:mediaObject:1b5e2711-81f5-45e0-a77f-3c0c47d60918",
					Type:    "MediaObject",
					Content: base64Image,
					ContentEncoding: Fat{
						ID:   "http://data.europa.eu/snb/encoding/6146cde7dd",
						Type: "Concept",
						InScheme: DiplomaInScheme{
							ID:   "http://data.europa.eu/snb/encoding/25831c2",
							Type: "ConceptScheme",
						},
						PrefLabel: DiplomaPrefLabel{
							En: "base64",
						},
					},
					ContentType: Fat{
						ID:   "", // set later
						Type: "Concept",
						InScheme: DiplomaInScheme{
							ID:   "http://publications.europa.eu/resource/authority/file-type",
							Type: "ConceptScheme",
						},
						PrefLabel: DiplomaPrefLabel{
							En: "", // set later
						},
						Notation: "file-type",
					},
				},
				Page: 1,
			},
			Language: Fat{
				ID:   "http://publications.europa.eu/resource/authority/language/ENG",
				Type: "Concept",
				InScheme: DiplomaInScheme{
					ID:   "http://publications.europa.eu/resource/authority/language",
					Type: "ConceptScheme",
				},
				PrefLabel: DiplomaPrefLabel{
					En: "en",
				},
				Notation: "language",
			},
		},
		PrimaryLanguage: Fat{
			ID:   "http://publications.europa.eu/resource/authority/language/ENG",
			Type: "Concept",
			InScheme: DiplomaInScheme{
				ID:   "http://publications.europa.eu/resource/authority/language",
				Type: "ConceptScheme",
			},
			Notation: "language",
			PrefLabel: DiplomaPrefLabel{
				En: "en",
			},
		},
		Language: Fat{
			ID:   "http://publications.europa.eu/resource/authority/language/ENG",
			Type: "Concept",
			InScheme: DiplomaInScheme{
				ID:   "http://publications.europa.eu/resource/authority/language",
				Type: "ConceptScheme",
			},
			Notation: "language",
			PrefLabel: DiplomaPrefLabel{
				En: "en",
			},
		},
		Title: Title{
			En: "A converted document from ELMO:1.7",
		},
	}

	switch imageContentType {
	case "jpg", "jpeg", "JPEG", "JPG", "png", "PNG":
		id := fmt.Sprintf("http://publications.europa.eu/resource/authority/file-type/%s", strings.ToUpper(imageContentType))
		d.DisplayParameter.IndividualDisplay.DisplayDetail.Image.ContentType.ID = id
		d.DisplayParameter.IndividualDisplay.DisplayDetail.Image.ContentType.PrefLabel.En = imageContentType
	}
}

func (d *DiplomaDocument) Marshal() (map[string]any, error) {
	data, err := json.Marshal(d)
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

type DisplayParameter struct {
	ID                string                   `json:"id"`
	Type              string                   `json:"type"`
	IndividualDisplay DiplomaIndividualDisplay `json:"individualDisplay"`
	DisplayDetail     DisplayDetail            `json:"displayDetail"`
	PrimaryLanguage   Fat                      `json:"primaryLanguage"`
	Language          Fat                      `json:"language"`
	Title             Title                    `json:"title"`
}

type Title struct {
	En string `json:"en"`
}

type DiplomaIndividualDisplay struct {
	ID            string        `json:"id"`
	Type          string        `json:"type"`
	DisplayDetail DisplayDetail `json:"displayDetail"`
	Language      Fat           `json:"language"`
}

type DisplayDetail struct {
	ID    string      `json:"id"`
	Type  string      `json:"type"`
	Image MediaObject `json:"image"`
	Page  int         `json:"page"`
}

type MediaObject struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	Content         string `json:"content"`
	ContentEncoding Fat    `json:"contentEncoding"`
	ContentType     Fat    `json:"contentType"`
}

type Fat struct {
	ID         string           `json:"id"`
	Type       string           `json:"type"`
	SchemaName string           `json:"schemaName,omitempty"`
	InScheme   DiplomaInScheme  `json:"inScheme"`
	PrefLabel  DiplomaPrefLabel `json:"prefLabel"`
	Notation   string           `json:"notation"`
	ContentURL string           `json:"contentURL,omitempty"`
}

type DiplomaInScheme struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type DiplomaPrefLabel struct {
	En string `json:"en"`
}
