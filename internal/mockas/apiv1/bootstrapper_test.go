package apiv1

import (
	"context"
	"fmt"
	"testing"
	"vc/pkg/helpers"
	"vc/pkg/model"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func TestBootstrapperConstructor(t *testing.T) {
	tts := []struct {
		name string
		want []uploadMock
	}{
		{
			name: "OK",
			want: []uploadMock{
				{
					Meta: &model.MetaData{
						AuthenticSource: "authentic_source_se",
						DocumentVersion: "1.0.0",
						DocumentType:    "EHIC",
						DocumentID:      "document_id_10",
						RealData:        false,
						Collect:         &model.Collect{ID: "collect_id_10", ValidUntil: 2147520172},
						Revocation: &model.Revocation{
							ID:        "9da40dc0",
							Revoked:   false,
							Reference: model.RevocationReference{AuthenticSource: "authentic_source_se", DocumentType: "EHIC", DocumentID: "document_id_10"},
							RevokedAt: 0,
							Reason:    "",
						},
						CredentialValidFrom:       1,
						CredentialValidTo:         2147520172,
						DocumentDataValidationRef: "",
					},
					Identities: []model.Identity{
						{
							AuthenticSourcePersonID: "10", FamilyName: "Castaneda", GivenName: "Carlos", BirthDate: "1970-01-10",
							Schema: &model.IdentitySchema{Name: "SE", Version: "1.0.0"},
						},
					},
					DocumentDisplay: &model.DocumentDisplay{Version: "1.0.0", Type: "EHIC", DescriptionStructured: map[string]any{"en": "issuer", "sv": "utfärdare"}},
					DocumentData: map[string]any{
						"competent_institution": map[string]any{"institution_country": "SE", "institution_id": "SE:1234", "institution_name": "institution_name_se"},
						"document_id":           "document_id_10",
						"period_entitlement":    map[string]any{"ending_date": "2038-01-19", "starting_date": "1970-01-01"},
						"social_security_pin":   "12345",
						"subject":               map[string]any{"date_of_birth": "1970-01-10", "family_name": "Castaneda", "forename": "Carlos"},
					},
					DocumentDataVersion: "1.0.0",
				},
				{
					Meta: &model.MetaData{
						AuthenticSource: "authentic_source_at",
						DocumentVersion: "1.0.0",
						DocumentType:    "EHIC",
						DocumentID:      "document_id_11",
						RealData:        false,
						Collect:         &model.Collect{ID: "collect_id_11", ValidUntil: 2147520172},
						Revocation: &model.Revocation{
							ID:        "9da40dc0",
							Revoked:   false,
							Reference: model.RevocationReference{AuthenticSource: "authentic_source_at", DocumentType: "EHIC", DocumentID: "document_id_11"},
							RevokedAt: 0,
							Reason:    "",
						},
						CredentialValidFrom:       1,
						CredentialValidTo:         2147520172,
						DocumentDataValidationRef: "",
					},
					Identities: []model.Identity{
						{
							AuthenticSourcePersonID: "11", FamilyName: "Howell", GivenName: "Lenna", BirthDate: "1935-02-21",
							Schema: &model.IdentitySchema{Name: "AT", Version: "1.0.0"},
						},
					},
					DocumentDisplay: &model.DocumentDisplay{Version: "1.0.0", Type: "EHIC",
						DescriptionStructured: map[string]any{"en": "issuer", "sv": "utfärdare"},
					},
					DocumentData: map[string]any{
						"competent_institution": map[string]any{
							"institution_country": "AT",
							"institution_id":      "AT:1234",
							"institution_name":    "institution_name_at",
						},
						"document_id":         "document_id_11",
						"period_entitlement":  map[string]any{"ending_date": "2038-01-19", "starting_date": "1970-01-01"},
						"social_security_pin": "12357",
						"subject":             map[string]any{"date_of_birth": "1935-02-21", "family_name": "Howell", "forename": "Lenna"},
					},
					DocumentDataVersion: "1.0.0",
				},
				{
					Meta: &model.MetaData{
						AuthenticSource: "authentic_source_de",
						DocumentVersion: "1.0.0",
						DocumentType:    "EHIC",
						DocumentID:      "document_id_12",
						RealData:        false,
						Collect:         &model.Collect{ID: "collect_id_12", ValidUntil: 2147520172},
						Revocation: &model.Revocation{
							ID:        "9da40dc0",
							Revoked:   false,
							Reference: model.RevocationReference{AuthenticSource: "authentic_source_de", DocumentType: "EHIC", DocumentID: "document_id_12"},
							RevokedAt: 0,
							Reason:    "",
						},
						CredentialValidFrom:       1,
						CredentialValidTo:         2147520172,
						DocumentDataValidationRef: "",
					},
					Identities: []model.Identity{
						{
							AuthenticSourcePersonID: "12", FamilyName: "Anderson", GivenName: "Ute", BirthDate: "1967-03-21",
							Schema: &model.IdentitySchema{Name: "DE", Version: "1.0.0"},
						},
					},
					DocumentData: map[string]any{
						"competent_institution": map[string]any{"institution_country": "DE", "institution_id": "DE:1234", "institution_name": "institution_name_de"},
						"document_id":           "document_id_12",
						"period_entitlement":    map[string]any{"ending_date": "2038-01-19", "starting_date": "1970-01-01"},
						"social_security_pin":   "98883123",
						"subject":               map[string]any{"date_of_birth": "1967-03-21", "family_name": "Anderson", "forename": "Ute"},
					},
					DocumentDataVersion: "1.0.0",
					DocumentDisplay:     &model.DocumentDisplay{Version: "1.0.0", Type: "EHIC", DescriptionStructured: map[string]any{"en": "issuer", "sv": "utfärdare"}},
				},
				{
					Meta: &model.MetaData{
						AuthenticSource: "authentic_source_nl",
						DocumentVersion: "1.0.0",
						DocumentType:    "EHIC",
						DocumentID:      "document_id_13",
						RealData:        false,
						Collect:         &model.Collect{ID: "collect_id_13", ValidUntil: 2147520172},
						Revocation: &model.Revocation{
							ID:        "9da40dc0",
							Revoked:   false,
							Reference: model.RevocationReference{AuthenticSource: "authentic_source_nl", DocumentType: "EHIC", DocumentID: "document_id_13"},
							RevokedAt: 0,
							Reason:    "",
						},
						CredentialValidFrom:       1,
						CredentialValidTo:         2147520172,
						DocumentDataValidationRef: "",
					},
					Identities: []model.Identity{
						{
							AuthenticSourcePersonID: "13", FamilyName: "Eelman", GivenName: "Olivia", BirthDate: "1971-03-13",
							Schema: &model.IdentitySchema{Name: "NL", Version: "1.0.0"},
						},
					},
					DocumentData: map[string]any{
						"competent_institution": map[string]any{"institution_country": "NL", "institution_id": "NL:1234", "institution_name": "institution_name_nl"},
						"document_id":           "document_id_13",
						"period_entitlement":    map[string]any{"ending_date": "2038-01-19", "starting_date": "1970-01-01"},
						"social_security_pin":   "097428358",
						"subject":               map[string]any{"date_of_birth": "1971-03-13", "family_name": "Eelman", "forename": "Olivia"},
					},
					DocumentDataVersion: "1.0.0",
					DocumentDisplay:     &model.DocumentDisplay{Version: "1.0.0", Type: "EHIC", DescriptionStructured: map[string]any{"en": "issuer", "sv": "utfärdare"}},
				},
				{
					Meta: &model.MetaData{
						AuthenticSource: "authentic_source_dk",
						DocumentVersion: "1.0.0",
						DocumentType:    "EHIC",
						DocumentID:      "document_id_14",
						RealData:        false,
						Collect:         &model.Collect{ID: "collect_id_14", ValidUntil: 2147520172},
						Revocation: &model.Revocation{
							ID:        "9da40dc0",
							Revoked:   false,
							Reference: model.RevocationReference{AuthenticSource: "authentic_source_dk", DocumentType: "EHIC", DocumentID: "document_id_14"},
							RevokedAt: 0,
							Reason:    "",
						},
						CredentialValidFrom:       1,
						CredentialValidTo:         2147520172,
						DocumentDataValidationRef: "",
					},
					Identities: []model.Identity{
						{
							AuthenticSourcePersonID: "14", FamilyName: "Høgh-Nørgaard Iversen", GivenName: "Patrick", BirthDate: "1994-03-07",
							Schema: &model.IdentitySchema{Name: "DK", Version: "1.0.0"},
						},
					},
					DocumentData: map[string]any{
						"competent_institution": map[string]any{"institution_country": "DK", "institution_id": "DK:1234", "institution_name": "institution_name_dk"},
						"document_id":           "document_id_14",
						"period_entitlement":    map[string]any{"ending_date": "2038-01-19", "starting_date": "1970-01-01"},
						"social_security_pin":   "449-49-2795",
						"subject":               map[string]any{"date_of_birth": "1994-03-07", "family_name": "Høgh-Nørgaard Iversen", "forename": "Patrick"},
					},
					DocumentDataVersion: "1.0.0",
					DocumentDisplay:     &model.DocumentDisplay{Version: "1.0.0", Type: "EHIC", DescriptionStructured: map[string]any{"en": "issuer", "sv": "utfärdare"}},
				},
				{
					Meta: &model.MetaData{
						AuthenticSource: "authentic_source_dk",
						DocumentVersion: "1.0.0",
						DocumentType:    "PDA1",
						DocumentID:      "document_id_20",
						RealData:        false,
						Collect:         &model.Collect{ID: "collect_id_20", ValidUntil: 2147520172},
						Revocation: &model.Revocation{
							ID:        "9da40dc0",
							Revoked:   false,
							Reference: model.RevocationReference{AuthenticSource: "authentic_source_dk", DocumentType: "PDA1", DocumentID: "document_id_20"},
							RevokedAt: 0,
							Reason:    "",
						},
						CredentialValidFrom:       1,
						CredentialValidTo:         2147520172,
						DocumentDataValidationRef: "",
					},
					Identities: []model.Identity{
						{
							AuthenticSourcePersonID: "20", FamilyName: "Christiansen", GivenName: "Mats", BirthDate: "1983-03-27",
							Schema: &model.IdentitySchema{Name: "DK", Version: "1.0.0"},
						},
					},
					DocumentData: map[string]any{
						"competent_institution": map[string]any{
							"country_code":     "DK",
							"institution_id":   "DK:1234",
							"institution_name": "institution_name_dk",
						},
						"decision_legislation_applicable": map[string]any{
							"ending_date":                            "2038-01-19",
							"starting_date":                          "1970-01-01",
							"member_state_which_legislation_applies": "DK",
							"transitional_rule_apply":                false,
						},
						"places_of_work": []any{
							map[string]any{
								"no_fixed_place_of_work_exist": false,
								"country_work":                 "DK",
								"place_of_work": []any{
									map[string]any{
										"flag_state_home_base": "DK",
										"company_vessel_name":  "vessel_name_dk",
										"address":              map[string]any{"street": "Møllestien 2", "post_code": "12332", "town": "Aarhus"},
										"ids_of_company": []any{
											map[string]any{"company_id": "3615c840", "type_of_id": "01"},
										},
									},
								},
							},
						},
						"details_of_employment": []any{
							map[string]any{
								"name":               "Corp inc.",
								"type_of_employment": "01",
								"address":            map[string]any{"country": "DK", "post_code": "12332", "street": "Møllestien 2", "town": "Aarhus"},
								"ids_of_employer": []any{
									map[string]any{"employer_id": "f7c317dc", "type_of_id": "01"},
								},
							},
						},
						"social_security_pin":              "98123",
						"nationality":                      []any{"DK"},
						"status_confirmation":              "01",
						"unique_number_of_issued_document": "asd123",
					},
					DocumentDataVersion: "1.0.0",
					DocumentDisplay:     &model.DocumentDisplay{Version: "1.0.0", Type: "PDA1", DescriptionStructured: map[string]any{"en": "issuer", "sv": "utfärdare"}},
				},
				{
					Meta: &model.MetaData{
						AuthenticSource: "authentic_source_de",
						DocumentVersion: "1.0.0",
						DocumentType:    "PDA1",
						DocumentID:      "document_id_21",
						RealData:        false,
						Collect:         &model.Collect{ID: "collect_id_21", ValidUntil: 2147520172},
						Revocation: &model.Revocation{
							ID:        "9da40dc0",
							Revoked:   false,
							Reference: model.RevocationReference{AuthenticSource: "authentic_source_de", DocumentType: "PDA1", DocumentID: "document_id_21"},
							RevokedAt: 0,
							Reason:    "",
						},
						CredentialValidFrom:       1,
						CredentialValidTo:         2147520172,
						DocumentDataValidationRef: "",
					},
					Identities: []model.Identity{
						{
							AuthenticSourcePersonID: "21", FamilyName: "Derichs", GivenName: "Aldrich", BirthDate: "1971-05-25",
							Schema: &model.IdentitySchema{Name: "DE", Version: "1.0.0"},
						},
					},
					DocumentData: map[string]any{
						"competent_institution": map[string]any{
							"country_code":     "DE",
							"institution_id":   "DE:1234",
							"institution_name": "institution_name_de",
						},
						"decision_legislation_applicable": map[string]any{
							"ending_date":                            "2038-01-19",
							"starting_date":                          "1970-01-01",
							"member_state_which_legislation_applies": "DE",
							"transitional_rule_apply":                false,
						},
						"places_of_work": []any{
							map[string]any{
								"no_fixed_place_of_work_exist": false,
								"country_work":                 "DE",
								"place_of_work": []any{
									map[string]any{
										"flag_state_home_base": "DE",
										"company_vessel_name":  "vessel_name_de",
										"address":              map[string]any{"street": "Petzoldstrasse 2", "post_code": "03042", "town": "Cottbus"},
										"ids_of_company": []any{
											map[string]any{"company_id": "3615c840", "type_of_id": "01"},
										},
									},
								},
							},
						},
						"details_of_employment": []any{
							map[string]any{
								"name":               "Corp inc.",
								"type_of_employment": "01",
								"address":            map[string]any{"country": "DE", "post_code": "47055", "street": "Masurenallee 33", "town": "Duisburg"},
								"ids_of_employer": []any{
									map[string]any{"employer_id": "f7c317dc", "type_of_id": "01"},
								},
							},
						},
						"social_security_pin":              "98123123",
						"nationality":                      []any{"DE"},
						"status_confirmation":              "01",
						"unique_number_of_issued_document": "asd123",
					},
					DocumentDataVersion: "1.0.0",
					DocumentDisplay:     &model.DocumentDisplay{Version: "1.0.0", Type: "PDA1", DescriptionStructured: map[string]any{"en": "issuer", "sv": "utfärdare"}},
				},
				{
					Meta: &model.MetaData{
						AuthenticSource: "authentic_source_se",
						DocumentVersion: "1.0.0",
						DocumentType:    "PDA1",
						DocumentID:      "document_id_22",
						RealData:        false,
						Collect:         &model.Collect{ID: "collect_id_22", ValidUntil: 2147520172},
						Revocation: &model.Revocation{
							ID:        "9da40dc0",
							Revoked:   false,
							Reference: model.RevocationReference{AuthenticSource: "authentic_source_se", DocumentType: "PDA1", DocumentID: "document_id_22"},
							RevokedAt: 0,
							Reason:    "",
						},
						CredentialValidFrom:       1,
						CredentialValidTo:         2147520172,
						DocumentDataValidationRef: "",
					},
					Identities: []model.Identity{
						{
							AuthenticSourcePersonID: "22", FamilyName: "Holmberg", GivenName: "Algot", BirthDate: "1955-11-25",
							Schema: &model.IdentitySchema{Name: "SE", Version: "1.0.0"},
						},
					},
					DocumentData: map[string]any{
						"competent_institution": map[string]any{
							"country_code":     "SE",
							"institution_id":   "SE:1234",
							"institution_name": "institution_name_se",
						},
						"decision_legislation_applicable": map[string]any{
							"ending_date":                            "2038-01-19",
							"starting_date":                          "1970-01-01",
							"member_state_which_legislation_applies": "SE",
							"transitional_rule_apply":                false,
						},
						"places_of_work": []any{
							map[string]any{
								"no_fixed_place_of_work_exist": false,
								"country_work":                 "SE",
								"place_of_work": []any{
									map[string]any{
										"flag_state_home_base": "SE",
										"company_vessel_name":  "vessel_name_se",
										"address":              map[string]any{"street": "Idrottsgatan 2", "post_code": "753 33", "town": "Uppsala"},
										"ids_of_company": []any{
											map[string]any{"company_id": "3615c840", "type_of_id": "01"},
										},
									},
								},
							},
						},
						"details_of_employment": []any{
							map[string]any{
								"name":               "Corp inc.",
								"type_of_employment": "01",
								"address":            map[string]any{"country": "SE", "post_code": "611 34", "street": "Östra Storgatan 10A", "town": "Nyköping"},
								"ids_of_employer": []any{
									map[string]any{"employer_id": "f7c317dc", "type_of_id": "01"},
								},
							},
						},
						"social_security_pin":              "12345",
						"nationality":                      []any{"SE"},
						"status_confirmation":              "01",
						"unique_number_of_issued_document": "asd123",
					},
					DocumentDataVersion: "1.0.0",
					DocumentDisplay:     &model.DocumentDisplay{Version: "1.0.0", Type: "PDA1", DescriptionStructured: map[string]any{"en": "issuer", "sv": "utfärdare"}},
				},
				{
					Meta: &model.MetaData{
						AuthenticSource: "authentic_source_nl",
						DocumentVersion: "1.0.0",
						DocumentType:    "PDA1",
						DocumentID:      "document_id_23",
						RealData:        false,
						Collect:         &model.Collect{ID: "collect_id_23", ValidUntil: 2147520172},
						Revocation: &model.Revocation{
							ID:        "9da40dc0",
							Revoked:   false,
							Reference: model.RevocationReference{AuthenticSource: "authentic_source_nl", DocumentType: "PDA1", DocumentID: "document_id_23"},
							RevokedAt: 0,
							Reason:    "",
						},
						CredentialValidFrom:       1,
						CredentialValidTo:         2147520172,
						DocumentDataValidationRef: "",
					},
					Identities: []model.Identity{
						{
							AuthenticSourcePersonID: "23", FamilyName: "Cicilia", GivenName: "Joep", BirthDate: "1999-07-29",
							Schema: &model.IdentitySchema{Name: "NL", Version: "1.0.0"},
						},
					},
					DocumentData: map[string]any{
						"competent_institution": map[string]any{
							"country_code":     "NL",
							"institution_id":   "NL:1234",
							"institution_name": "institution_name_nl",
						},
						"decision_legislation_applicable": map[string]any{
							"ending_date":                            "2038-01-19",
							"starting_date":                          "1970-01-01",
							"member_state_which_legislation_applies": "NL",
							"transitional_rule_apply":                false,
						},
						"places_of_work": []any{
							map[string]any{
								"no_fixed_place_of_work_exist": false,
								"country_work":                 "NL",
								"place_of_work": []any{
									map[string]any{
										"flag_state_home_base": "NL",
										"company_vessel_name":  "vessel_name_nl",
										"address":              map[string]any{"street": "Het Rond 6", "post_code": "3701 HS", "town": "Zeist"},
										"ids_of_company": []any{
											map[string]any{"company_id": "3615c840", "type_of_id": "01"},
										},
									},
								},
							},
						},
						"details_of_employment": []any{
							map[string]any{
								"name":               "Corp inc.",
								"type_of_employment": "01",
								"address":            map[string]any{"country": "NL", "post_code": "9712 HM", "street": "Oude Ebbingestraat 68", "town": "Groningen"},
								"ids_of_employer": []any{
									map[string]any{"employer_id": "f7c317dc", "type_of_id": "01"},
								},
							},
						},
						"social_security_pin":              "753841605",
						"nationality":                      []any{"NL"},
						"status_confirmation":              "01",
						"unique_number_of_issued_document": "asd123",
					},
					DocumentDataVersion: "1.0.0",
					DocumentDisplay:     &model.DocumentDisplay{Version: "1.0.0", Type: "PDA1", DescriptionStructured: map[string]any{"en": "issuer", "sv": "utfärdare"}},
				},
				{
					Meta: &model.MetaData{
						AuthenticSource: "authentic_source_at",
						DocumentVersion: "1.0.0",
						DocumentType:    "PDA1",
						DocumentID:      "document_id_24",
						RealData:        false,
						Collect:         &model.Collect{ID: "collect_id_24", ValidUntil: 2147520172},
						Revocation: &model.Revocation{
							ID:        "9da40dc0",
							Revoked:   false,
							Reference: model.RevocationReference{AuthenticSource: "authentic_source_at", DocumentType: "PDA1", DocumentID: "document_id_24"},
							RevokedAt: 0,
							Reason:    "",
						},
						CredentialValidFrom:       1,
						CredentialValidTo:         2147520172,
						DocumentDataValidationRef: "",
					},
					Identities: []model.Identity{
						{
							AuthenticSourcePersonID: "24", FamilyName: "Hoeger", GivenName: "Hollis", BirthDate: "1983-05-05",
							Schema: &model.IdentitySchema{Name: "AT", Version: "1.0.0"},
						},
					},
					DocumentData: map[string]any{
						"competent_institution": map[string]any{
							"country_code":     "AT",
							"institution_id":   "AT:1234",
							"institution_name": "institution_name_at",
						},
						"decision_legislation_applicable": map[string]any{
							"ending_date":                            "2038-01-19",
							"starting_date":                          "1970-01-01",
							"member_state_which_legislation_applies": "AT",
							"transitional_rule_apply":                false,
						},
						"places_of_work": []any{
							map[string]any{
								"no_fixed_place_of_work_exist": false,
								"country_work":                 "AT",
								"place_of_work": []any{
									map[string]any{
										"flag_state_home_base": "AT",
										"company_vessel_name":  "vessel_name_at",
										"address":              map[string]any{"street": "Stumpergasse 48/8", "post_code": "1060", "town": "Wien"},
										"ids_of_company": []any{
											map[string]any{"company_id": "3615c840", "type_of_id": "01"},
										},
									},
								},
							},
						},
						"details_of_employment": []any{
							map[string]any{
								"name":               "Corp inc.",
								"type_of_employment": "01",
								"address":            map[string]any{"country": "AT", "post_code": "4810", "street": "Franz-Josef-Platz 3", "town": "Gmunden"},
								"ids_of_employer": []any{
									map[string]any{"employer_id": "f7c317dc", "type_of_id": "01"},
								},
							},
						},
						"social_security_pin":              "315-95-2501",
						"nationality":                      []any{"AT"},
						"status_confirmation":              "01",
						"unique_number_of_issued_document": "asd123",
					},
					DocumentDataVersion: "1.0.0",
					DocumentDisplay:     &model.DocumentDisplay{Version: "1.0.0", Type: "PDA1", DescriptionStructured: map[string]any{"en": "issuer", "sv": "utfärdare"}},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				deterministicMocks: []uploadMock{},
			}

			err := c.bootstrapperConstructor(context.Background())
			assert.NoError(t, err)

			if diff := cmp.Diff(tt.want, c.deterministicMocks); diff != "" {
				t.Errorf("diff: mismatch (-want +got):\n%s", diff)
			}

			assert.Len(t, c.deterministicMocks, 10)

			for index, mock := range c.deterministicMocks {
				if err := helpers.CheckSimple(mock); err != nil {
					t.Errorf("CheckSimple failed %v", err)
				}
				fmt.Printf("\n%s:%d\n", mock.Identities[0].GivenName, 1234+index)
				fmt.Printf("subject-id: %s\n", mock.Identities[0].AuthenticSourcePersonID)
				fmt.Printf("givenName: %s\n", mock.Identities[0].GivenName)
				fmt.Printf("sn: %s\n", mock.Identities[0].FamilyName)
				fmt.Printf("schacDateOfBirth: %s\n\n", mock.Identities[0].BirthDate)
			}

		})
	}
}
