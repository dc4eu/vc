package apiv1

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type ELMService struct {
	Client *Client
}

func (s *ELMService) random(ctx context.Context, person *person) (map[string]any, error) {
	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	b, err := os.ReadFile(filepath.Join("../../../standards", "elm_3_2.json"))
	if err != nil {
		return nil, err
	}

	doc := map[string]any{}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}

	return doc, nil
}
