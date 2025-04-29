package bootstrapper

import "vc/pkg/socialsecurity"

func (c *Client) MakeEHIC() {
	c.ehic["70"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "23451235",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-09-08",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003464995",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["71"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "34873567",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-04-21",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003707285",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["72"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "76841223",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2024-03-14",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003665621",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["73"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "83865760",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2024-04-01",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003861950",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["74"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "39738563",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-04-29",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003502921",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["75"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "29899548",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-09-12",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003929691",

		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["76"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "52712842",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-09-06",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003667017",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["77"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "42388599",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2024-03-28",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003508607",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["78"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "44460320",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2024-01-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003670006",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["79"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "71509226",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-10-30",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003874563",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["80"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "42393788",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{

			StartingDate: "2023-01-22",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003980686",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["81"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "86368354",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-08-08",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003808930",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}
	c.ehic["82"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "61350638",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-10",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003930680",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["83"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "40046784",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-12-26",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003420696",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["84"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "80387895",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-02-18",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003975414",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["85"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "57381544",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-11-18",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003483005",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["86"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "79785792",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2024-03-08",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003431583",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["87"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "87299198",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-08-15",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003465348",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["88"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "44715442",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-05-27",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003882863",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["89"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "70501734",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-04-21",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003582443",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["90"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "27713953",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-10-04",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003850509",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["91"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "74070435",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-01-23",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003517908",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["92"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "87416368",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-02",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003715709",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}
	c.ehic["93"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "33133266",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-01",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003767929",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["94"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "86154445",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-08",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003668716",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["95"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "55625776",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-08",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003841233",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["96"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "43568744",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-08",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003671438",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["97"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "65664926",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-08",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003630878",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["98"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "37400178",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2024-02-10",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003757763",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["99"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "41191495",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-12-31",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003991122",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["100"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "40046784",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-12-26",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003420696",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["101"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "80387895",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-02-18",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003975414",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}
	c.ehic["102"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "57381544",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-11-18",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003483005",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["103"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "79785792",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2024-03-08",
			EndingDate:   "2026-04-12",
		},

		DocumentID: "80246802460003431583",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}
	c.ehic["104"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "87299198",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-08-15",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003465348",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["105"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "44715442",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-05-27",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003882863",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}
	c.ehic["106"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "70501734",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-04-21",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003582443",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}
	c.ehic["107"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "27713953",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-10-04",

			EndingDate: "2026-04-12",
		},
		DocumentID: "80246802460003850509",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["108"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "74070435",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-01-23",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003517908",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["109"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "87416368",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-02",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003715709",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["110"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "33133266",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-01",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003767929",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["111"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "86154445",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-08",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003668716",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["112"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "55625776",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-08",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003841233",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["113"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "43568744",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-08",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003671438",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["114"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "65664926",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-08",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003630878",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}
	c.ehic["115"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "85734926",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2024-02-10",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "80246802460003630878",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}
	c.ehic["116"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "87451234",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-12-31",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "45678901234567890123",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}
	c.ehic["117"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "23987456",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-12-26",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "12345678901234567890",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}
	c.ehic["118"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "98765432",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-02-18",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "98765432109876543210",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["119"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "12345678",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-11-18",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "23456789012345678901",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["120"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "45678901",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2024-03-08",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "34567890123456789012",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["121"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "23456789",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-08-15",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "56789012345678901234",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["122"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "34567890",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-05-27",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "67890123456789012345",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["123"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "56789012",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-04-21",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "78901234567890123456",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["124"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "67890123",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-10-04",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "89012345678901234567",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["125"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "78901234",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-01-23",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "90123456789012345678",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["126"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "89012345",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-02",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "34567890123456789012",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["127"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "90123456",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "45678901234567890123",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["128"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "34561278",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "56789012345678901234",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["129"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "45672389",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "67890123456789012345",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["130"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "56783490",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "78901234567890123456",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}
	c.ehic["131"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "67894501",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-04-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "89012345678901234567",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["132"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "78905612",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2024-04-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "90123456789012345678",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["133"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "89016723",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-04-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "12345678901234567890",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["134"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "90127834",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-04-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "23456789012345678901",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}
	c.ehic["135"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "12348945",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-02-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "34567890123456789012",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}
	c.ehic["136"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "23459056",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-11-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "45678901234567890123",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}
	c.ehic["137"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "34560167",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2024-03-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "56789012345678901234",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["138"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "45671278",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-08-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "67890123456789012345",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["139"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "56782389",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "78901234567890123456",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["140"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "67893490",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-04-21",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "89012345678901234567",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["141"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "78904501",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "90123456789012345678",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["142"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "89015612",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "12345678901234567890",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["143"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "90126723",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "23456789012345678901",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["144"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "12337834",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "34567890123456789012",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["145"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "23448945",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "45678901234567890123",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["146"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "34559056",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "56789012345678901234",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["147"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "45660167",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "67890123456789012345",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["148"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "92330167",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "78901234567890123456",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}

	c.ehic["149"] = socialsecurity.EHICDocument{
		SocialSecurityPin: "80440167",
		PeriodEntitlement: socialsecurity.PeriodEntitlement{
			StartingDate: "2023-03-13",
			EndingDate:   "2026-04-12",
		},
		DocumentID: "87101234567890123433",
		CompetentInstitution: socialsecurity.CompetentInstitution{
			InstitutionID:      "CLEISS",
			InstitutionName:    "Groupe Caisse des Dépôts assisted by the Centre of European and International Liaisons for Social Security",
			InstitutionCountry: "FR",
		},
	}
}
