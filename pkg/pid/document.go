package pid

import (
	"encoding/json"
	"vc/pkg/model"
)

type Document struct {
	Identity        *model.Identity `json:"identity,omitempty"  bson:"identity,omitempty"  validate:"required"`
	DocumentType    string          `json:"document_type" bson:"document_type" validate:"required"`
	AuthenticSource string          `json:"authentic_source" bson:"authentic_source" validate:"required"`
}

func (d *Document) Marshal() (map[string]any, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}

	var data map[string]any
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, err
	}

	return data, nil
}
