package model

var mockPDA1Map = map[string]any{
	"person": map[string]any{
		"forename":      "test_value",
		"family_name":   "asdasd",
		"date_of_birth": "1990-01-01",
		"other_elements": map[string]any{
			"sex":                  "98",
			"forename_at_birth":    "test_value",
			"family_name_at_birth": "test_value",
		},
	},
	"social_security_pin": "test_value",
	"nationality": []string{
		"SE",
	},
	"details_of_employment": []any{
		map[string]any{
			"type_of_employment": "01",
			"name":               "test_value",
			"address": map[string]any{
				"street":      "test_value",
				"town":        "test_value",
				"postal_code": "test_value",
				"country":     "SE",
			},
			"ids_of_employer": []any{
				map[string]any{
					"employer_id": "SE:1234",
					"type_of_id":  "01",
				},
			},
		},
	},
	"places_of_work": []any{
		map[string]any{
			"no_fixed_place_of_work_exist": false,
			"country_work":                 "SE",
			"place_of_work": []any{
				map[string]any{
					"company_vessel_name":  "test_value",
					"flag_state_home_base": "SE",
					"ids_of_company":       []string{"SE:1234"},
					"address": map[string]any{
						"street":      "test_value",
						"town":        "test_value",
						"postal_code": "test_value",
					},
				},
			},
		},
	},
	"decision_legislation_applicable": map[string]any{
		"member_state_which_legislation_applies": "SE",
		"transitional_rules_apply":               false,
		"starting_date":                          "1990-01-01",
		"ending_date":                            "1990-01-02",
	},
	"status_confirmation":              "02",
	"unique_number_of_issued_document": "SE1234",
	"competent_institution": map[string]any{
		"institution_id":   "SE:12345",
		"institution_name": "test_value",
		"country_code":     "SE",
	},
}

var mockEHICMap = map[string]any{
	"subject": map[string]any{
		"forename":      "test_value",
		"family_name":   "asdasd",
		"date_of_birth": "1990-01-01",
		"other_elements": map[string]any{
			"sex":                  "98",
			"forename_at_birth":    "test_value",
			"family_name_at_birth": "test_value",
		},
	},
	"social_security_pin": "test_value",
	"period_entitlement": map[string]any{
		"starting_date": "1990-01-01",
		"ending_date":   "1990-01-01",
	},
	"document_id": "asd",
	"competent_institution": map[string]any{
		"institution_id":      "SE:1234",
		"institution_name":    "test_value",
		"institution_country": "SE",
	},
}
