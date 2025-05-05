package apiv1

import (
	"context"
	"time"
	"vc/pkg/identity"

	"github.com/brianvoe/gofakeit/v6"
)

type PIDService struct {
	Client *Client
}

func (s *PIDService) random(ctx context.Context, person *person) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	doc := identity.PIDDocument{
		GivenName:  person.sa.FirstName,
		FamilyName: person.sa.LastName,
		BirthDate:  gofakeit.Date().Format("2006-01-02"),
	}

	return doc.Marshal()

}
