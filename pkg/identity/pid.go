package identity

import "encoding/json"

type PIDDocument struct {
	GivenName  string `json:"given_name" validate:"required"`
	FamilyName string `json:"family_name" validate:"required"`
	BirthDate  string `json:"birth_date" validate:"required"`
}

// Marshal marshals the document to a map
func (d *PIDDocument) Marshal() (map[string]any, error) {
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
