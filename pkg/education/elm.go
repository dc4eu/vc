package education

import "encoding/json"

type ELMDocument map[string]any

// Marshal marshals the document to a map
func (d *ELMDocument) Marshal() (map[string]any, error) {
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

type Data struct {
	ID         string `json:"id"`
	Notation   string `json:"notation"`
	SchemeName string `json:"schemeName"`
	Type       string `json:"type"`
}

type Identifier Data
