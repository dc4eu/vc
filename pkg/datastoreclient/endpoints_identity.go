package datastoreclient

import (
	"context"
	"fmt"
	"net/http"
	"vc/pkg/model"
)

type identityService struct {
	client  *Client
	service string
}

// IdentityMappingQuery is the query for IdentityMapping
type IdentityMappingQuery struct {
	AuthenticSource string          `json:"authentic_source"`
	Identity        *model.Identity `json:"identity"`
}

// Mapping maps an identity, return authentic_source_person_id
func (s *identityService) Mapping(ctx context.Context, query *IdentityMappingQuery) (string, *http.Response, error) {
	url := fmt.Sprintf("%s/%s", s.service, "mapping")
	reply := ""
	resp, err := s.client.call(ctx, http.MethodPost, url, nil, reply)
	if err != nil {
		return "", resp, err
	}
	return reply, resp, nil
}
