package pid

import (
	"encoding/json"
	"vc/pkg/model"
)

type Document struct {
	*model.Identity
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
