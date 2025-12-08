package db

import (
	"context"
	"vc/pkg/model"
)

// AuthorizationContextStore defines the interface for authorization context operations
type AuthorizationContextStore interface {
	Save(ctx context.Context, doc *model.AuthorizationContext) error
	Get(ctx context.Context, query *model.AuthorizationContext) (*model.AuthorizationContext, error)
	GetWithAccessToken(ctx context.Context, token string) (*model.AuthorizationContext, error)
	ForfeitAuthorizationCode(ctx context.Context, query *model.AuthorizationContext) (*model.AuthorizationContext, error)
	Consent(ctx context.Context, query *model.AuthorizationContext) error
	AddToken(ctx context.Context, code string, token *model.Token) error
	SetAuthenticSource(ctx context.Context, query *model.AuthorizationContext, authenticSource string) error
	AddIdentity(ctx context.Context, query *model.AuthorizationContext, input *model.AuthorizationContext) error
}

// Ensure concrete types implement the interfaces
var _ AuthorizationContextStore = (*AuthorizationContextColl)(nil)
